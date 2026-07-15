package sysstat

import (
	"os"
	"runtime"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/process"

	"github.com/SimoneErrigo/Janus/backend/internal/cache"
	"github.com/SimoneErrigo/Janus/backend/internal/sniffer"
)

var startTime = time.Now()

// Stats holds a snapshot of system metrics.
type Stats struct {
	CPU        CPUStats     `json:"cpu"`
	RAM        RAMStats     `json:"ram"`
	Disk       DiskStats    `json:"disk"`
	Process    ProcessStats `json:"process"`
	Capture    CaptureStats `json:"capture"`
	DBSizeMB   float64      `json:"db_size_mb"`
	RedisMemMB *float64     `json:"redis_mem_mb,omitempty"`
	UptimeSecs int64        `json:"uptime_secs"`
}

type CaptureStats struct {
	QueueDropped uint64 `json:"queue_dropped"`
	WriterErrors uint64 `json:"writer_errors"`
}

type CPUStats struct {
	UsagePercent float64 `json:"usage_percent"`
}

type RAMStats struct {
	TotalMB      float64 `json:"total_mb"`
	UsedMB       float64 `json:"used_mb"`
	AvailableMB  float64 `json:"available_mb"`
	UsagePercent float64 `json:"usage_percent"`
}

type DiskStats struct {
	TotalMB      float64 `json:"total_mb"`
	UsedMB       float64 `json:"used_mb"`
	AvailableMB  float64 `json:"available_mb"`
	UsagePercent float64 `json:"usage_percent"`
}

type ProcessStats struct {
	RSSMB          float64 `json:"rss_mb"`
	GoroutineCount int     `json:"goroutine_count"`
}

// Collector gathers system stats.
type Collector struct {
	packetStore *sniffer.PacketStore
	cacheClient *cache.Client
	dataDir     string
}

// NewCollector creates a new stats collector.
func NewCollector(packetStore *sniffer.PacketStore, cacheClient *cache.Client, dataDir string) *Collector {
	return &Collector{
		packetStore: packetStore,
		cacheClient: cacheClient,
		dataDir:     dataDir,
	}
}

// Collect gathers a full snapshot of system metrics.
func (c *Collector) Collect() (*Stats, error) {
	s := &Stats{
		UptimeSecs: int64(time.Since(startTime).Seconds()),
	}

	// CPU
	// interval=0 uses the delta maintained by gopsutil and returns immediately;
	// the stats endpoint must not pause the control plane on every refresh.
	cpuPercent, err := cpu.Percent(0, false)
	if err == nil && len(cpuPercent) > 0 {
		s.CPU.UsagePercent = cpuPercent[0]
	}

	// RAM
	vmem, err := mem.VirtualMemory()
	if err == nil {
		s.RAM.TotalMB = float64(vmem.Total) / 1024 / 1024
		s.RAM.UsedMB = float64(vmem.Used) / 1024 / 1024
		s.RAM.AvailableMB = float64(vmem.Available) / 1024 / 1024
		s.RAM.UsagePercent = vmem.UsedPercent
	}

	// Disk (partition where data/ resides)
	diskPath := c.dataDir
	if diskPath == "" {
		diskPath = "/"
	}
	usage, err := disk.Usage(diskPath)
	if err == nil {
		s.Disk.TotalMB = float64(usage.Total) / 1024 / 1024
		s.Disk.UsedMB = float64(usage.Used) / 1024 / 1024
		s.Disk.AvailableMB = float64(usage.Free) / 1024 / 1024
		s.Disk.UsagePercent = usage.UsedPercent
	}

	// Process stats
	pid := int32(os.Getpid())
	proc, err := process.NewProcess(pid)
	if err == nil {
		memInfo, err := proc.MemoryInfo()
		if err == nil {
			s.Process.RSSMB = float64(memInfo.RSS) / 1024 / 1024
		}
	}
	s.Process.GoroutineCount = runtime.NumGoroutine()

	// DB size
	if c.packetStore != nil {
		dbSize, err := c.packetStore.DBSize()
		if err == nil {
			s.DBSizeMB = float64(dbSize) / 1024 / 1024
		}
		s.Capture.QueueDropped, s.Capture.WriterErrors = c.packetStore.WriterStats()
	}

	// Redis memory
	if c.cacheClient != nil {
		redisMem := c.cacheClient.MemoryUsageMB()
		if redisMem >= 0 {
			s.RedisMemMB = &redisMem
		}
	}

	return s, nil
}
