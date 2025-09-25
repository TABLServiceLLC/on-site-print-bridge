SHELL := /bin/bash

.PHONY: run token print-test

# Base URL, terminal id, and printer IP for commands
BASE ?= https://localhost:8443
TID ?= t1
IP ?= $(PRINTER_IP)

run:
	npm start

token:
	@node -e "require('dotenv').config(); console.log(require('jsonwebtoken').sign({ sub: 'local-test' }, process.env.JWT_SECRET || 'replace-with-your-secret'))"

print-test:
	@[ -n "$(IP)" ] || { echo "Missing printer IP. Use: make print-test IP=<printer-ip> (or set PRINTER_IP env var)"; exit 1; }
	@TOKEN=$$(node -e "require('dotenv').config(); console.log(require('jsonwebtoken').sign({ sub: 'local-test' }, process.env.JWT_SECRET || 'replace-with-your-secret'))"); \
	DATA=$$(node -e "process.stdout.write(Buffer.from('Hello\n','utf8').toString('base64'))"); \
	echo "Assigning $(TID) -> $(IP)"; \
	curl -ksSf -H "Authorization: Bearer $$TOKEN" -H "Content-Type: application/json" \
	  -d "{\"terminalId\":\"$(TID)\",\"ip\":\"$(IP)\"}" "$(BASE)/assign" >/dev/null; \
	echo "Sending test print to $(IP) as $(TID)..."; \
	curl -ksSf -H "Authorization: Bearer $$TOKEN" -H "Content-Type: application/json" \
	  -d "{\"terminalId\":\"$(TID)\",\"data\":\"$$DATA\"}" "$(BASE)/print"; \
	echo; echo "Done."

