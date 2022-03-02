# go-httpdebug

Go utilities to help debug HTTP requests.

## Rationale

While maintaining the [github.com/google/go-github](https://github.com/google/go-github)
repo, I've realized that the vast majority of reported "issues" actually could be
resolved by the user of the repo if they had an easy way to duplicate the
GitHub v3 API call using the equivalent `curl` command. However, it is not always
a simple matter to figure out that that command should actually be.

This repo provides a simple `http.RoundTripper` that, when added as an additional
`Transport`, will dump out the equivalent `curl` command for every request made
through it (to `os.Stderr`).

## Simple usage

If you have a simple `http.Client`, then you can add `CurlTransport` like this:

```go
ct := httpdebug.New()
c := &http.Client{Transport: ct}
...
```

## Usage with existing Transport

If your client already uses a transport, you can inject it like this:

```go
import (
  dbg "github.com/gmlewis/go-httpdebug/httpdebug"
  "github.com/google/go-github/v43/github"
  "golang.org/x/oauth2"
)
...
ctx := context.Background()
ts := oauth2.StaticTokenSource(
	&oauth2.Token{AccessToken: token},
)
tc := oauth2.NewClient(ctx, ts)

ct := dbg.New(dbg.WithTransport(tc.Transport))
client := github.NewClient(ct.Client())
```

----------------------------------------------------------------------

# License

Copyright 2022 Glenn M. Lewis. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
