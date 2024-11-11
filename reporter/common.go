// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package reporter // import "go.opentelemetry.io/ebpf-profiler/reporter"

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"time"

	lru "github.com/elastic/go-freelru"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/xsync"
)

var (
	cgroupv2PathPattern = regexp.MustCompile(`0:.*?:(.*)`)
)

type cgroupv2IDCache = *lru.SyncedLRU[libpf.PID, string]
type hostmetadataCache = *lru.SyncedLRU[string, string]
type executablesCache = *lru.SyncedLRU[libpf.FileID, execInfo]
type traceEventsCache = *xsync.RWMutex[map[traceAndMetaKey]*traceEvents]
type framesCache = *lru.SyncedLRU[libpf.FileID, *xsync.RWMutex[map[libpf.AddressOrLineno]sourceInfo]]

func getReporterCaches(cfg *Config) (executablesCache, framesCache, cgroupv2IDCache, hostmetadataCache, traceEventsCache, error) {
	executables, err :=
		lru.NewSynced[libpf.FileID, execInfo](cfg.ExecutablesCacheElements, libpf.FileID.Hash32)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	executables.SetLifetime(1 * time.Hour) // Allow GC to clean stale items.

	frames, err := lru.NewSynced[libpf.FileID,
		*xsync.RWMutex[map[libpf.AddressOrLineno]sourceInfo]](
		cfg.FramesCacheElements, libpf.FileID.Hash32)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	frames.SetLifetime(1 * time.Hour) // Allow GC to clean stale items.

	cgroupv2ID, err := lru.NewSynced[libpf.PID, string](cfg.CGroupCacheElements,
		func(pid libpf.PID) uint32 { return uint32(pid) })
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	// Set a lifetime to reduce risk of invalid data in case of PID reuse.
	cgroupv2ID.SetLifetime(90 * time.Second)

	// Next step: Dynamically configure the size of this LRU.
	// Currently, we use the length of the JSON array in
	// hostmetadata/hostmetadata.json.
	hostmetadata, err := lru.NewSynced[string, string](115, hashString)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	traceEvents := xsync.NewRWMutex(map[traceAndMetaKey]*traceEvents{})

	return executables, frames, cgroupv2ID, hostmetadata, &traceEvents, nil
}

// lookupCgroupv2 returns the cgroupv2 ID for pid.
func lookupCgroupv2(cgroupv2ID cgroupv2IDCache, pid libpf.PID) (string, error) {
	id, ok := cgroupv2ID.Get(pid)
	if ok {
		return id, nil
	}

	// Slow path
	f, err := os.Open(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", err
	}
	defer f.Close()

	var genericCgroupv2 string
	scanner := bufio.NewScanner(f)
	buf := make([]byte, 512)
	// Providing a predefined buffer overrides the internal buffer that Scanner uses (4096 bytes).
	// We can do that and also set a maximum allocation size on the following call.
	// With a maximum of 4096 characters path in the kernel, 8192 should be fine here. We don't
	// expect lines in /proc/<PID>/cgroup to be longer than that.
	scanner.Buffer(buf, 8192)
	var pathParts []string
	for scanner.Scan() {
		line := scanner.Text()
		pathParts = cgroupv2PathPattern.FindStringSubmatch(line)
		if pathParts == nil {
			log.Debugf("Could not extract cgroupv2 path from line: %s", line)
			continue
		}
		genericCgroupv2 = pathParts[1]
		break
	}

	// Cache the cgroupv2 information.
	// To avoid busy lookups, also empty cgroupv2 information is cached.
	cgroupv2ID.Add(pid, genericCgroupv2)

	return genericCgroupv2, nil
}

type locLine struct {
	fnIdx uint64
	line  int64
}

type locationHandler interface {
	Add(address uint64, mapping uint64, attributes []uint64, line *locLine)
}

type mappingHandler interface {
	Add(memStart, memLimit, fileOffset uint64, fileNameIdx int64, attrIndices []uint64)
}

// profileAttributeHandler provides a generic way to add attributes to a map.
type profileAttributeHandler interface {
	PutStr(key string, value string)
	PutInt(key string, value int64)
	Len() int
}

// attributeMap is a temporary cache to hold attribute key to index into
// an attribute table mappings.
type attributeMap map[string]uint64

// stringMap ...
type stringMap map[string]uint32

// funcMap ...
type funcMap map[funcInfo]uint64

// addProfileAttributes adds attributes to Profile.attribute_table and returns
// the indices to these attributes.
func addProfileAttributes[T string | int64](p profileAttributeHandler,
	attributes []attrKeyValue[T], attrMap attributeMap) []uint64 {
	indices := make([]uint64, 0, len(attributes))

	addAttr := func(attr attrKeyValue[T]) {
		var attributeCompositeKey string

		switch val := any(attr.value).(type) {
		case string:
			if val == "" {
				log.Warnf("Skipping empty attribute for '%s'", attr.key)
				return
			}
			attributeCompositeKey = attr.key + "_" + val
		case int64:
			attributeCompositeKey = attr.key + "_" + strconv.Itoa(int(val))
		default:
			log.Errorf("Unsupported attribute value type for '%s'. Only string and int64 are supported.",
				attr.key)
			return
		}

		if attributeIndex, exists := attrMap[attributeCompositeKey]; exists {
			indices = append(indices, attributeIndex)
			return
		}

		newIndex := uint64(p.Len())
		indices = append(indices, newIndex)
		switch val := any(attr.value).(type) {
		case string:
			p.PutStr(attr.key, val)
		case int64:
			p.PutInt(attr.key, val)
		}
		attrMap[attributeCompositeKey] = newIndex
	}

	for i := range attributes {
		addAttr(attributes[i])
	}

	return indices
}

// addFrameMetadata accepts metadata associated witha a frame and caches it.
func addFrameMetadata(frames framesCache, args *FrameMetadataArgs) {
	fileID := args.FrameID.FileID()
	addressOrLine := args.FrameID.AddressOrLine()

	if frameMapLock, exists := frames.Get(fileID); exists {
		frameMap := frameMapLock.WLock()
		defer frameMapLock.WUnlock(&frameMap)

		sourceFile := args.SourceFile
		if sourceFile == "" {
			// The new SourceFile may be empty, and we don't want to overwrite
			// an existing filePath with it.
			if s, exists := (*frameMap)[addressOrLine]; exists {
				sourceFile = s.filePath
			}
		}

		(*frameMap)[addressOrLine] = sourceInfo{
			lineNumber:     args.SourceLine,
			filePath:       sourceFile,
			functionOffset: args.FunctionOffset,
			functionName:   args.FunctionName,
		}
		return
	}

	v := make(map[libpf.AddressOrLineno]sourceInfo)
	v[addressOrLine] = sourceInfo{
		lineNumber:     args.SourceLine,
		filePath:       args.SourceFile,
		functionOffset: args.FunctionOffset,
		functionName:   args.FunctionName,
	}
	mu := xsync.NewRWMutex(v)
	frames.Add(fileID, &mu)
}

// reportTraceEvent enqueues reported trace events for the Collector reporter.
func reportTraceEvent(traceEventsCache traceEventsCache, cgroupv2ID cgroupv2IDCache,
	trace *libpf.Trace, meta *TraceEventMeta) {
	traceEventsMap := traceEventsCache.WLock()
	defer traceEventsCache.WUnlock(&traceEventsMap)

	containerID, err := lookupCgroupv2(cgroupv2ID, meta.PID)
	if err != nil {
		log.Debugf("Failed to get a cgroupv2 ID as container ID for PID %d: %v",
			meta.PID, err)
	}

	key := traceAndMetaKey{
		hash:           trace.Hash,
		comm:           meta.Comm,
		apmServiceName: meta.APMServiceName,
		containerID:    containerID,
	}

	if events, exists := (*traceEventsMap)[key]; exists {
		events.timestamps = append(events.timestamps, uint64(meta.Timestamp))
		(*traceEventsMap)[key] = events
		return
	}

	(*traceEventsMap)[key] = &traceEvents{
		files:              trace.Files,
		linenos:            trace.Linenos,
		frameTypes:         trace.FrameTypes,
		mappingStarts:      trace.MappingStart,
		mappingEnds:        trace.MappingEnd,
		mappingFileOffsets: trace.MappingFileOffsets,
		timestamps:         []uint64{uint64(meta.Timestamp)},
	}
}

func populateTrace(attrHandler profileAttributeHandler,
	mH mappingHandler, locH locationHandler,
	exeCache executablesCache, framesCache framesCache,
	traceInfo *traceEvents,
	strMap stringMap, fnMap funcMap, attrMap attributeMap) {
	// Temporary lookup to reference existing Mappings.
	fileIDtoMapping := make(map[libpf.FileID]uint64)

	// Walk every frame of the trace.
	for i := range traceInfo.frameTypes {
		frameAttributes := addProfileAttributes(attrHandler, []attrKeyValue[string]{
			{key: "profile.frame.type", value: traceInfo.frameTypes[i].String()},
		}, attrMap)

		var locationMappingIndex uint64
		var ll *locLine

		switch frameKind := traceInfo.frameTypes[i]; frameKind {
		case libpf.NativeFrame:
			// As native frames are resolved in the backend, we use Mapping to
			// report these frames.

			if tmpMappingIndex, exists := fileIDtoMapping[traceInfo.files[i]]; exists {
				locationMappingIndex = tmpMappingIndex
			} else {
				idx := uint64(len(fileIDtoMapping))
				fileIDtoMapping[traceInfo.files[i]] = idx
				locationMappingIndex = idx

				execInfo, exists := exeCache.Get(traceInfo.files[i])

				// Next step: Select a proper default value,
				// if the name of the executable is not known yet.
				var fileName = "UNKNOWN"
				if exists {
					fileName = execInfo.fileName
				}

				mappingAttributes := addProfileAttributes(attrHandler, []attrKeyValue[string]{
					// Once SemConv and its Go package is released with the new
					// semantic convention for build_id, replace these hard coded
					// strings.
					{key: "process.executable.build_id.gnu", value: execInfo.gnuBuildID},
					{key: "process.executable.build_id.profiling",
						value: traceInfo.files[i].StringNoQuotes()},
				}, attrMap)

				mH.Add(uint64(traceInfo.mappingStarts[i]), uint64(traceInfo.mappingEnds[i]),
					traceInfo.mappingFileOffsets[i], int64(getStringMapIndex(strMap, fileName)),
					mappingAttributes)
			}
		case libpf.AbortFrame:
			// Next step: Figure out how the OTLP protocol
			// could handle artificial frames, like AbortFrame,
			// that are not originated from a native or interpreted
			// program.
		default:
			fileIDInfoLock, exists := framesCache.Get(traceInfo.files[i])
			if !exists {
				// At this point, we do not have enough information for the frame.
				// Therefore, we report a dummy entry and use the interpreter as filename.
				ll = &locLine{
					fnIdx: createFunctionEntry(fnMap, "UNREPORTED", frameKind.String()),
				}
			} else {
				fileIDInfo := fileIDInfoLock.RLock()
				if si, exists := (*fileIDInfo)[traceInfo.linenos[i]]; exists {
					ll = &locLine{
						fnIdx: createFunctionEntry(fnMap, si.functionName, si.filePath),
						line:  int64(si.lineNumber),
					}
				} else {
					// At this point, we do not have enough information for the frame.
					// Therefore, we report a dummy entry and use the interpreter as filename.
					// To differentiate this case from the case where no information about
					// the file ID is available at all, we use a different name for reported
					// function.
					ll = &locLine{
						fnIdx: createFunctionEntry(fnMap, "UNRESOLVED", frameKind.String()),
					}
				}
				fileIDInfoLock.RUnlock(&fileIDInfo)
			}

			// To be compliant with the protocol, generate a dummy mapping entry.
			locationMappingIndex = getDummyMappingIndex(fileIDtoMapping, strMap,
				mH, traceInfo.files[i])
		}
		locH.Add(uint64(traceInfo.linenos[i]), locationMappingIndex, frameAttributes, ll)
	}
}

// getDummyMappingIndex inserts or looks up an entry for interpreted FileIDs.
func getDummyMappingIndex(fileIDtoMapping map[libpf.FileID]uint64,
	strMap stringMap, mH mappingHandler, fileID libpf.FileID) uint64 {
	if tmpMappingIndex, exists := fileIDtoMapping[fileID]; exists {
		return tmpMappingIndex
	}
	idx := uint64(len(fileIDtoMapping))
	fileIDtoMapping[fileID] = idx

	mH.Add(0, 0, 0, int64(getStringMapIndex(strMap, "")), []uint64{})
	return idx
}

// getStringMapIndex inserts or looks up the index for value in stringMap.
func getStringMapIndex(strMap stringMap, value string) uint32 {
	if idx, exists := strMap[value]; exists {
		return idx
	}

	idx := uint32(len(strMap))
	strMap[value] = idx

	return idx
}

// createFunctionEntry adds a new function and returns its reference index.
func createFunctionEntry(fnMap funcMap, name string, fileName string) uint64 {
	key := funcInfo{
		name:     name,
		fileName: fileName,
	}
	if idx, exists := fnMap[key]; exists {
		return idx
	}

	idx := uint64(len(fnMap))
	fnMap[key] = idx

	return idx
}
