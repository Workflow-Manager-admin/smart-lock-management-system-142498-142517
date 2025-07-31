#!/bin/bash
cd /home/kavia/workspace/code-generation/smart-lock-management-system-142498-142517/smart_lock_backend
source venv/bin/activate
flake8 .
LINT_EXIT_CODE=$?
if [ $LINT_EXIT_CODE -ne 0 ]; then
  exit 1
fi

