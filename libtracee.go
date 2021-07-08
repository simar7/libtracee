package libtracee

import (
	"fmt"
	"os"

	"github.com/aquasecurity/tracee/tracee-ebpf/tracee"
	"github.com/aquasecurity/tracee/tracee-ebpf/tracee/external"

	"github.com/aquasecurity/tracee/tracee-rules/engine"
	"github.com/aquasecurity/tracee/tracee-rules/types"
)

func SetupTracee(sigs []types.Signature, inputEventsCount int, bpfObjectPath string) (*int, chan types.Finding, error) {
	traceeEventsChan, traceeRulesInputChan, done, trcE, err := setupTraceeBPF(inputEventsCount, bpfObjectPath)
	if err != nil {
		return nil, nil, err
	}

	var eventsProcessed int
	go func() {
		eventForwarder(traceeEventsChan, traceeRulesInputChan, &eventsProcessed)
	}()

	outputChan := make(chan types.Finding, inputEventsCount)
	e, err := engine.NewEngine(sigs, engine.EventSources{Tracee: traceeRulesInputChan}, outputChan, os.Stderr)
	if err != nil {
		return nil, nil, err
	}

	go func() {
		fmt.Println("starting tracee-ebpf...")
		err = trcE.Run()
		if err != nil {
			panic(err)
		}
	}()

	go func() {
		fmt.Println("starting tracee-rules....")
		e.Start(done)
	}()
	return &eventsProcessed, outputChan, nil
}

func AddNSigs(sigFuncs []func() (types.Signature, error)) []types.Signature {
	var sigs []types.Signature
	for _, sf := range sigFuncs {
		s, err := sf()
		if err != nil {
			panic(err)
		}
		sigs = append(sigs, s)
	}
	return sigs
}

func defaultTraceeConfig(eventsToTrace []int32, traceeEventsChan chan external.Event, tmpDir string, bpfObjectPath string) tracee.Config {
	return tracee.Config{
		Filter: &tracee.Filter{
			UIDFilter:     &tracee.UintFilter{},
			PIDFilter:     &tracee.UintFilter{},
			MntNSFilter:   &tracee.UintFilter{},
			PidNSFilter:   &tracee.UintFilter{},
			CommFilter:    &tracee.StringFilter{},
			UTSFilter:     &tracee.StringFilter{},
			ContFilter:    &tracee.BoolFilter{},
			NewContFilter: &tracee.BoolFilter{},
			ArgFilter:     &tracee.ArgFilter{},
			RetFilter:     &tracee.RetFilter{},
			NewPidFilter:  &tracee.BoolFilter{},
			EventsToTrace: eventsToTrace,
		},
		Capture:            &tracee.CaptureConfig{OutputPath: tmpDir},
		ChanEvents:         traceeEventsChan,
		BPFObjPath:         bpfObjectPath,
		Output:             &tracee.OutputConfig{Format: "table"},
		PerfBufferSize:     1024,
		BlobPerfBufferSize: 1024,
	}
}

func setupTraceeBPF(inputEventsCount int, bpfObjectPath string) (chan external.Event, chan types.Event, chan bool, *tracee.Tracee, error) {
	// channel for tracee ebpf to send events to
	traceeEventsChan := make(chan external.Event, inputEventsCount)
	traceeRulesInputChan := make(chan types.Event, inputEventsCount)
	done := make(chan bool, 1)

	eventsToTrace := []int32{122, 268, 6, 57, 165, 292, 106, 157, 269, 59, 92, 49, 217, 310, 1006, 87, 133, 429, 50, 259, 329, 113, 123, 175, 439, 319, 94, 313, 2, 5, 78, 32, 3, 105, 114, 42, 56, 435, 62, 101, 90, 166, 260, 257, 43, 51, 322, 176, 266, 1022, 321, 85, 41, 311, 4, 21, 1004, 1016, 91, 437, 436, 93, 1015, 263, 58, 33, 1014, 88, 288} // TODO: Export prepareEventsToTrace() in Tracee
	trcE, err := tracee.New(defaultTraceeConfig(eventsToTrace, traceeEventsChan, "/tmp/tracee", bpfObjectPath))
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return traceeEventsChan, traceeRulesInputChan, done, trcE, err
}

// Event forwarder from tracee-ebpf to tracee-rules
func eventForwarder(traceeEventsChan chan external.Event, traceeRulesInputChan chan types.Event, totalEvents *int) {
	for {
		select {
		case event := <-traceeEventsChan:
			//fmt.Println(event)
			traceeRulesInputChan <- event // TODO: We need to use same channel types for tracee-ebpf output and tracee-rules input
			*totalEvents += 1
		}
	}
}
