package virtio

const (
	FeatureNetCSUM              uint64 = 1 << 0
	FeatureNetGuestCSUM         uint64 = 1 << 1
	FeatureNetCtrlGuestOffloads uint64 = 1 << 2
	FeatureNetMTU               uint64 = 1 << 3
	FeatureNetMAC               uint64 = 1 << 5
	FeatureNetGSO               uint64 = 1 << 6
	FeatureNetGuestRSC4         uint64 = 1 << 41
	FeatureNetGuestRSC6         uint64 = 1 << 42
	FeatureNetGuestTSO4         uint64 = 1 << 7
	FeatureNetGuestTSO6         uint64 = 1 << 8
	FeatureNetGuestECN          uint64 = 1 << 9
	FeatureNetGuestUFO          uint64 = 1 << 10
	FeatureNetHostTSO4          uint64 = 1 << 11
	FeatureNetHostTSO6          uint64 = 1 << 12
	FeatureNetHostECN           uint64 = 1 << 13
	FeatureNetHostUFO           uint64 = 1 << 14
	FeatureNetMRGRXBUF          uint64 = 1 << 15
	FeatureNetSTATUS            uint64 = 1 << 16
	FeatureNetCtrlVQ            uint64 = 1 << 17
	FeatureNetCtrlRX            uint64 = 1 << 18
	FeatureNetCtrlVLAN          uint64 = 1 << 19
	FeatureNetGuestAnnounce     uint64 = 1 << 21
	FeatureNetMQ                uint64 = 1 << 22
	FeatureNetCtrlMACAddr       uint64 = 1 << 23
	FeatureNetHostUSO           uint64 = 1 << 56
	FeatureNetHashReport        uint64 = 1 << 57
	FeatureNetGuestHdrLen       uint64 = 1 << 59
	FeatureNetRSS               uint64 = 1 << 60
	FeatureNetRSCExt            uint64 = 1 << 61
	FeatureNetStandby           uint64 = 1 << 62
	FeatureNetSpeedDuplex       uint64 = 1 << 63
)
