// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package reporter // import "go.opentelemetry.io/ebpf-profiler/reporter"

import (
	"context"
	"maps"
	"slices"
	"time"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/collector/consumer/consumerprofiles"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pprofile"
	semconv "go.opentelemetry.io/otel/semconv/v1.25.0"

	"go.opentelemetry.io/ebpf-profiler/libpf"
)

// Assert that we implement the full Reporter interface.
var _ Reporter = (*CollectorReporter)(nil)

// CollectorReporter receives and transforms information to be Collector Collector compliant.
type CollectorReporter struct {
	cfg          *Config
	nextConsumer consumerprofiles.Profiles

	// stopSignal is the stop signal for shutting down all background tasks.
	stopSignal chan struct{}

	// hostmetadata stores metadata that is sent out with every request.
	hostmetadata hostmetadataCache

	// executables stores metadata for executables.
	executables executablesCache

	// cgroupv2ID caches PID to container ID information for cgroupv2 containers.
	cgroupv2ID cgroupv2IDCache

	// frames maps frame information to its source location.
	frames framesCache

	// traceEvents stores reported trace events (trace metadata with frames and counts)
	traceEvents traceEventsCache

	// samplesPerSecond is the number of samples per second.
	samplesPerSecond int
}

// NewCollector builds a new CollectorReporter
func NewCollector(cfg *Config, nextConsumer consumerprofiles.Profiles) (*CollectorReporter, error) {
	executables, frames, cgroupv2ID, hostmetadata, traceEvents, err := getReporterCaches(cfg)
	if err != nil {
		return nil, err
	}

	return &CollectorReporter{
		cfg:          cfg,
		nextConsumer: nextConsumer,

		executables:  executables,
		frames:       frames,
		hostmetadata: hostmetadata,
		traceEvents:  traceEvents,
		cgroupv2ID:   cgroupv2ID,

		samplesPerSecond: cfg.SamplesPerSecond,
	}, nil
}

func (r *CollectorReporter) Start(context.Context) error {
	go func() {
		tick := time.NewTicker(r.cfg.ReportInterval)
		defer tick.Stop()
		purgeTick := time.NewTicker(5 * time.Minute)
		defer purgeTick.Stop()

		for {
			select {
			case <-r.stopSignal:
				return
			case <-tick.C:
				if err := r.reportProfile(context.Background()); err != nil {
					log.Errorf("Request failed: %v", err)
				}
				tick.Reset(libpf.AddJitter(r.cfg.ReportInterval, 0.2))
			case <-purgeTick.C:
				// Allow the GC to purge expired entries to avoid memory leaks.
				r.executables.PurgeExpired()
				r.frames.PurgeExpired()
			}
		}
	}()

	return nil
}

// ExecutableKnown returns true if the metadata of the Executable specified by fileID is
// cached in the reporter.
func (r *CollectorReporter) ExecutableKnown(fileID libpf.FileID) bool {
	_, known := r.executables.Get(fileID)
	return known
}

// ExecutableMetadata accepts a fileID with the corresponding filename
// and caches this information.
func (r *CollectorReporter) ExecutableMetadata(args *ExecutableMetadataArgs) {
	r.executables.Add(args.FileID, execInfo{
		fileName:   args.FileName,
		gnuBuildID: args.GnuBuildID,
	})
}

// FrameKnown return true if the metadata of the Frame specified by frameID is
// cached in the reporter.
func (r *CollectorReporter) FrameKnown(frameID libpf.FrameID) bool {
	known := false
	if frameMapLock, exists := r.frames.Get(frameID.FileID()); exists {
		frameMap := frameMapLock.RLock()
		defer frameMapLock.RUnlock(&frameMap)
		_, known = (*frameMap)[frameID.AddressOrLine()]
	}
	return known
}

// FrameMetadata accepts metadata associated with a frame and caches this information.
func (r *CollectorReporter) FrameMetadata(args *FrameMetadataArgs) {
	addFrameMetadata(r.frames, args)
}

// GetMetrics returns internal metrics of CollectorReporter.
func (r *CollectorReporter) GetMetrics() Metrics {
	return Metrics{}
}

// ReportFramesForTrace is a NOP for CollectorReporter.
func (r *CollectorReporter) ReportFramesForTrace(_ *libpf.Trace) {}

// ReportCountForTrace is a NOP for CollectorReporter.
func (r *CollectorReporter) ReportCountForTrace(_ libpf.TraceHash, _ uint16, _ *TraceEventMeta) {
}

// ReportMetrics is a NOP for CollectorReporter.
func (r *CollectorReporter) ReportMetrics(_ uint32, _ []uint32, _ []int64) {}

func (r *CollectorReporter) Stop() {
	close(r.stopSignal)
}

// ReportHostMetadata enqueues host metadata.
func (r *CollectorReporter) ReportHostMetadata(metadataMap map[string]string) {
	for k, v := range metadataMap {
		r.hostmetadata.Add(k, v)
	}
}

func (r *CollectorReporter) SupportsReportTraceEvent() bool { return true }

// ReportHostMetadataBlocking enqueues host metadata.
func (r *CollectorReporter) ReportHostMetadataBlocking(_ context.Context,
	metadataMap map[string]string, _ int, _ time.Duration) error {
	r.ReportHostMetadata(metadataMap)
	return nil
}

// ReportTraceEvent enqueues reported trace events for the Collector reporter.
func (r *CollectorReporter) ReportTraceEvent(trace *libpf.Trace, meta *TraceEventMeta) {
	if r.nextConsumer == nil {
		return
	}

	reportTraceEvent(r.traceEvents, r.cgroupv2ID, trace, meta)
}

// getProfile sets the data an OTLP profile with all collected samples up to
// this moment.
func (r *CollectorReporter) setProfile(profile pprofile.Profile) (startTS,
	endTS pcommon.Timestamp) {
	traceEvents := r.traceEvents.WLock()
	samples := maps.Clone(*traceEvents)
	clear(*traceEvents)
	r.traceEvents.WUnlock(&traceEvents)

	// stringMap is a temporary helper that will build the StringTable.
	// By specification, the first element should be empty.
	strMap := make(stringMap)
	strMap[""] = 0

	// funcMap is a temporary helper that will build the Function array
	// in profile and make sure information is deduplicated.
	fnMap := make(funcMap)
	fnMap[funcInfo{name: "", fileName: ""}] = 0

	// attrMap is a temporary helper that maps attribute values to
	// their respective indices.
	// This is to ensure that AttributeTable does not contain duplicates.
	attrMap := make(attributeMap)

	st := profile.SampleType().AppendEmpty()
	st.SetType(int64(getStringMapIndex(strMap, "samples")))
	st.SetUnit(int64(getStringMapIndex(strMap, "count")))

	pt := profile.PeriodType()
	pt.SetType(int64(getStringMapIndex(strMap, "cpu")))
	pt.SetUnit(int64(getStringMapIndex(strMap, "nanoseconds")))
	profile.SetPeriod(1e9 / int64(r.samplesPerSecond))

	locationIndex := uint64(0)

	for traceKey, traceInfo := range samples {
		sample := profile.Sample().AppendEmpty()
		sample.SetLocationsStartIndex(locationIndex)

		sample.SetStacktraceIdIndex(getStringMapIndex(strMap,
			traceKey.hash.Base64()))

		slices.Sort(traceInfo.timestamps)
		startTS = pcommon.Timestamp(traceInfo.timestamps[0])
		endTS = pcommon.Timestamp(traceInfo.timestamps[len(traceInfo.timestamps)-1])

		sample.TimestampsUnixNano().FromRaw(traceInfo.timestamps)
		sample.Value().Append(1)

		populateTrace(profile.AttributeTable(), getpdataMappingHandlerWrapper(profile.Mapping()),
			getpdataLocationHandlingWrapper(profile.Location()),
			r.executables, r.frames, traceInfo, strMap, fnMap, attrMap)

		sampleAttrs := append(addProfileAttributes(profile.AttributeTable(), []attrKeyValue[string]{
			{key: string(semconv.ContainerIDKey), value: traceKey.containerID},
			{key: string(semconv.ThreadNameKey), value: traceKey.comm},
			{key: string(semconv.ServiceNameKey), value: traceKey.apmServiceName},
		}, attrMap), addProfileAttributes(profile.AttributeTable(), []attrKeyValue[int64]{
			{key: string(semconv.ProcessPIDKey), value: traceKey.pid},
		}, attrMap)...)

		sample.Attributes().FromRaw(sampleAttrs)

		sample.SetLocationsLength(uint64(len(traceInfo.frameTypes)))
		locationIndex += sample.LocationsLength()
	}
	log.Debugf("Reporting OTLP profile with %d samples", profile.Sample().Len())

	// Populate the deduplicated functions into profile.
	for v := range fnMap {
		f := profile.Function().AppendEmpty()
		f.SetName(int64(getStringMapIndex(strMap, v.name)))
		f.SetFilename(int64(getStringMapIndex(strMap, v.fileName)))
	}

	// When ranging over stringMap, the order will be according to the
	// hash value of the key. To get the correct order for profile.StringTable,
	// put the values in stringMap, in the correct array order.
	stringTable := make([]string, len(strMap))
	for v, idx := range strMap {
		stringTable[idx] = v
	}

	for _, v := range stringTable {
		profile.StringTable().Append(v)
	}

	// profile.LocationIndices is not optional, and we only write elements into
	// profile.Location that at least one sample references.
	for i := int64(0); i < int64(profile.Location().Len()); i++ {
		profile.LocationIndices().Append(i)
	}

	profile.SetDuration(endTS - startTS)
	profile.SetStartTime(startTS)

	return startTS, endTS
}

// reportProfile sends a profile to the next consumer
func (r *CollectorReporter) reportProfile(ctx context.Context) error {
	profiles := pprofile.NewProfiles()
	rp := profiles.ResourceProfiles().AppendEmpty()

	sp := rp.ScopeProfiles().AppendEmpty()

	pc := sp.Profiles().AppendEmpty()
	pc.SetProfileID(pprofile.ProfileID(mkProfileID()))

	startTS, endTS := r.setProfile(pc.Profile())
	pc.SetStartTime(startTS)
	pc.SetEndTime(endTS)

	if pc.Profile().Sample().Len() == 0 {
		log.Debugf("Skip sending of profile to collector with no samples")
		return nil
	}

	return r.nextConsumer.ConsumeProfiles(ctx, profiles)
}

var _ mappingHandler = (*collectorMappingWrapper)(nil)

type collectorMappingWrapper struct {
	pprofile.Profile
}

func (p *collectorMappingWrapper) Add(memStart, memLimit, fileOffset uint64, fileNameIdx int64, attrIndices []uint64) {
	mapping := p.Mapping().AppendEmpty()
	mapping.SetMemoryStart(memStart)
	mapping.SetMemoryLimit(memLimit)
	mapping.SetFileOffset(fileOffset)
	mapping.SetFilename(fileNameIdx)
	mapping.Attributes().FromRaw(attrIndices)
}

var _ mappingHandler = (*pdataMappingWrapper)(nil)

type pdataMappingWrapper struct {
	pprofile.MappingSlice
}

func getpdataMappingHandlerWrapper(p pprofile.MappingSlice) *pdataMappingWrapper {
	return &pdataMappingWrapper{p}
}

func (w *pdataMappingWrapper) Add(memStart, memLimit, fileOffset uint64, fileNameIdx int64, attrIndices []uint64) {
	mapping := w.AppendEmpty()
	mapping.SetMemoryStart(memStart)
	mapping.SetMemoryLimit(memLimit)
	mapping.SetFileOffset(fileOffset)
	mapping.SetFilename(fileNameIdx)
	mapping.Attributes().FromRaw(attrIndices)
}

var _ locationHandler = (*pdataLocationWrapper)(nil)

type pdataLocationWrapper struct {
	pprofile.LocationSlice
}

func getpdataLocationHandlingWrapper(p pprofile.LocationSlice) *pdataLocationWrapper {
	return &pdataLocationWrapper{p}
}

func (w *pdataLocationWrapper) Add(address uint64, mapping uint64, attributes []uint64, ll *locLine) {
	loc := w.AppendEmpty()
	loc.SetAddress(address)
	loc.Attributes().FromRaw(attributes)
	loc.SetMappingIndex(mapping)
	if ll != nil {
		line := loc.Line().AppendEmpty()
		line.SetFunctionIndex(ll.fnIdx)
		line.SetLine(ll.line)
	}
}
