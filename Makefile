BINARY_NAME := ssh-watch-gnome
SRC_DIR := ./cmd/ssh-watch-gnome
BUILD_DIR := ./bin
INSTALL_DIR := $(HOME)/.local/bin
SYSTEMD_USER_DIR := $(HOME)/.config/systemd/user
CONFIG_DIR := $(HOME)/.config/ssh-watch-gnome

.PHONY: all build test clean install uninstall

all: build

build:
	@mkdir -p $(BUILD_DIR)
	go build -ldflags="-s -w" -o $(BUILD_DIR)/$(BINARY_NAME) $(SRC_DIR)

test:
	go test -v -race ./...

clean:
	rm -rf $(BUILD_DIR)

install: build
	@mkdir -p $(INSTALL_DIR)
	install -m 755 $(BUILD_DIR)/$(BINARY_NAME) $(INSTALL_DIR)/$(BINARY_NAME)
	@mkdir -p $(SYSTEMD_USER_DIR)
	install -m 644 systemd/$(BINARY_NAME).service $(SYSTEMD_USER_DIR)/$(BINARY_NAME).service
	@mkdir -p $(CONFIG_DIR)
	@if [ ! -f $(CONFIG_DIR)/config.json ]; then \
		cp config.example.json $(CONFIG_DIR)/config.json; \
		echo "Default configuration copied to $(CONFIG_DIR)/config.json"; \
	fi
	@echo "Installation complete. Binary installed at $(INSTALL_DIR)/$(BINARY_NAME)."
	@echo "Run 'systemctl --user daemon-reload && systemctl --user enable --now $(BINARY_NAME).service' to start the service."

uninstall:
	rm -f $(INSTALL_DIR)/$(BINARY_NAME)
	rm -f $(SYSTEMD_USER_DIR)/$(BINARY_NAME).service
	@echo "Uninstalled $(BINARY_NAME) from $(INSTALL_DIR) and $(SYSTEMD_USER_DIR)."
