[Unit]
Description=RNSEchoBot
After=network.target

[Service]
User=root
WorkingDirectory=/root/RNSEchobot
ExecStart=/bin/python3 /root/RNSEchobot/RNSEchobot.py -s --config /root/.reticulum
Restart=on-failure

[Install]
WantedBy=multi-user.target
