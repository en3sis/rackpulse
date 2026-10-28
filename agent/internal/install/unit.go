package install

const (
	serviceName = "rackpulse-agent"
	userName    = "rackpulse"
	binPath     = "/usr/local/bin/rackpulse-agent"
	unitPath    = "/etc/systemd/system/rackpulse-agent.service"
)

const unitFile = `[Unit]
Description=Rackpulse agent
After=network-online.target docker.service tailscaled.service
Wants=network-online.target

[Service]
User=rackpulse
Group=rackpulse
ExecStart=/usr/local/bin/rackpulse-agent run
Restart=always
RestartSec=5
StateDirectory=rackpulse-agent
StateDirectoryMode=0700
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
CapabilityBoundingSet=
AmbientCapabilities=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
`
