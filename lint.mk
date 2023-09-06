export WORKING_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
export LINT_IMAGE := erikjseidel/pylint-docker
export APP_DIR := /app
export PYLINTRC := /var/cache/.pylintrc

.PHONY: link
lint:
	docker run --rm -v $(WORKING_DIR)/$(APP_DIR):$(APP_DIR)/ -v $(WORKING_DIR)/.pylintrc:$(PYLINTRC) -i $(LINT_IMAGE) pylint --rcfile=$(PYLINTRC) $(APP_DIR)
