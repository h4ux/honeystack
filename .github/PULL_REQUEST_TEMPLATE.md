## What this changes

<!-- One or two sentences. What behaviour is different after this PR? -->

## Why

<!-- The problem being solved. Link the issue if there is one: Fixes #123 -->

## How it was tested

<!-- Be concrete: a `nc` transcript, the test you added, a screenshot of the
     dashboard, the output of the deploy script in a container. -->

- [ ] `gofmt -l .` is clean and `go vet -mod=vendor ./...` passes
- [ ] `go test -race -mod=vendor ./...` passes
- [ ] `node --check` passes for any changed dashboard file
- [ ] `bash -n` passes for any changed script

## For a new or changed honeypot service

- [ ] It never executes, forwards, relays, tunnels or delivers anything
- [ ] UDP replies are never larger than the request (no amplification)
- [ ] All reads are bounded and it survives garbage input
- [ ] Registered in `main.go`, defaulted in `config.default.json`, given an
      icon in `webapp/icons.js`
- [ ] Wire-format parsing has a test, and the service tables in
      `go-honeypot/README.md` are updated

## Anything reviewers should watch out for

<!-- Trade-offs, follow-ups you deliberately left out, risky bits. -->
