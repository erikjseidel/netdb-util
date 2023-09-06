export WORKING_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
export BLACK_IMAGE := pyfound/black
export APP_DIR := /app

.PHONY: format
format:
	docker run --rm -v $(WORKING_DIR)/$(APP_DIR):$(APP_DIR)/ $(BLACK_IMAGE) black --fast --skip-string-normalization $(APP_DIR)/

.PHONY: black
black:
	docker run --rm -v $(WORKING_DIR)/$(APP_DIR):$(APP_DIR)/ $(BLACK_IMAGE) black --fast --skip-string-normalization --check $(APP_DIR)/
