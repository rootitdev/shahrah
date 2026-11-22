# Google AI routing (client)

PasarGuard merges these rules into the subscription JSON. The template in
`src/shahrah/client_template.py` already sends the domains below to outbound
tag `proxy` (prepended by the panel).

After changing the template on the master:

```bash
shahrah panel client-template --update
# optional iOS-only template (assign per user in panel — not global default):
shahrah panel client-template --name IOS --profile ios --update
```

Domains forced through the tunnel (in addition to default non-Iran traffic):

- `gemini.google.com`, `aistudio.google.com`, `ai.google.dev`
- `generativelanguage.googleapis.com`, `makersuite.google.com`, `notebooklm.google.com`
- `googleapis.com`, `googleusercontent.com`, `gstatic.com`, `googlevideo.com`

If a product still fails, open the site in a browser with devtools and add any
missing hostnames to `GOOGLE_AI_DOMAINS` in `client_template.py`, then re-upload.