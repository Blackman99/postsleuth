# Sourced (hidden) by demo.tape: build postsleuth, write demo fixtures relative to now.
set -e
REPO=$(pwd)
go build -o /tmp/psdemo-bin/postsleuth ./cmd/postsleuth
mkdir -p /tmp/psdemo && python3 testdata/gen.py "$(date +%s)" /tmp/psdemo
export PATH=/tmp/psdemo-bin:$PATH PS1='\[\e[38;2;0;135;111m\]mx1\[\e[0m\] $ '
cd /tmp/psdemo
set +e
