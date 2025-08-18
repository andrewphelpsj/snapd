#!/bin/bash
seq 1 4 | xargs -I{} echo "demo-{}" | xargs -I{} multipass launch --name {} noble
