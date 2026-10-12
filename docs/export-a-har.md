# Export a HAR (and keep your cookies out of it)

A HAR is the browser's own record of a session's network traffic. Contour needs nothing else. Only capture apps you own, or that you have **written** authorization to observe (see [LEGAL.md](../LEGAL.md)).

A HAR contains cookies, tokens and response bodies, so treat it like a password file:

- prefer a staging environment and a test account
- log out when you're done, so the captured session tokens stop working
- never commit a HAR (this repo's `.gitignore` already ignores `*.har`) and delete it once the spec exists

Contour itself never copies a header or body value into its output. It only records that an `Authorization` or `Cookie` header was present. The steps below protect the file itself, not just Contour's output.

## 1. Record

Work through the flows you want documented. List things, open one, create one, update one, and trigger an error or two (an invalid form, a missing id). Every operation you hit two or more times gets a higher confidence score, and every error you trigger documents an error response.

### Chrome, Edge, Brave (Chromium)

1. Open DevTools (`F12`, or `Cmd+Opt+I` on macOS) and go to the **Network** tab.
2. Tick **Preserve log**. Optionally, click the **Fetch/XHR** filter to hide images and scripts. Contour skips static assets anyway.
3. Use the app.
4. Click the **Export HAR** (download arrow) button in the Network toolbar, or right-click the request list and choose **Save all as HAR**.

Recent Chrome versions export a *sanitized* HAR by default, without cookies or authorization headers. That's the safest option. Its only cost is that the spec may not list a security scheme, and you can add that by hand.

### Firefox

1. Open the Network Monitor (`Ctrl+Shift+E`, or `Cmd+Opt+E` on macOS).
2. In the gear menu (⚙), enable **Persist Logs**.
3. Use the app.
4. Right-click the request list and choose **Save All As HAR**.

Firefox includes cookies and authorization headers. Mask them before sharing the file (step 2).

### Safari

1. Enable the developer tools: *Settings → Advanced → Show features for web developers* (older versions: *Show Develop menu in menu bar*).
2. Open *Develop → Show Web Inspector* and go to the **Network** tab. Enable **Preserve Log**.
3. Use the app.
4. Click **Export** in the Network tab toolbar to save a `.har` file.

Safari includes cookies and authorization headers. Mask them before sharing the file (step 2).

## 2. Mask headers before the file travels

This keeps header *names*, so Contour still sees that requests were authenticated. It replaces the *values* and empties the cookie arrays:

```bash
jq '(.log.entries[] | (.request.headers[]?, .response.headers[]?)
     | select(.name | test("^(authorization|cookie|set-cookie|x-api-key)$"; "i")) | .value) |= "REDACTED"
  | (.log.entries[] | .request.cookies, .response.cookies) |= []' session.har > session.clean.har
```

Add any custom auth header your app uses to the list. Response bodies can still contain tokens, for example a login response with an `access_token`. Contour won't copy them, but the file still holds them. That's another reason to use a test account and to log out afterwards.

## 3. Compile

```bash
python3 -m contour analyze session.clean.har --host api.yourapp.com --openapi openapi.json
python3 -m contour sdk openapi.json -o sdk_out
```

`--host` keeps one API and drops analytics, CDNs and third-party widgets. Without it, Contour merges every host it sees and lists them in the gaps.

Read the gaps it prints. Each one tells you what to capture next.
