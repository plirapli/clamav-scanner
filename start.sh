#!/bin/sh

docker compose up -d --remove-orphans clamav kafka kafka-init kafka-ui
