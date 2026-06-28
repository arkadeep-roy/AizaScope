# AizaScope Endpoint Map

AizaScope only uses public, documented Google/Firebase REST/API surfaces and deterministic evidence classification.

## Firebase / Identity Toolkit

- `GET https://www.googleapis.com/identitytoolkit/v3/relyingparty/getProjectConfig?key={KEY}`
- `POST https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={KEY}`
- `POST https://identitytoolkit.googleapis.com/v1/accounts:delete?key={KEY}`

## Firestore

- `GET https://firestore.googleapis.com/v1/projects/{PROJECT}/databases/(default)/documents/{COLLECTION}?pageSize=1&mask.fieldPaths=__name__`
- `POST https://firestore.googleapis.com/v1/projects/{PROJECT}/databases/(default)/documents:listCollectionIds`
- `POST https://firestore.googleapis.com/v1/projects/{PROJECT}/databases/(default)/documents/{PROBE_PATH}` for marker write proof after read/list exposure


### Firestore candidate collection strategy

Firestore does not normally expose collection names. AizaScope therefore tests a practical built-in candidate set such as `users`, `profiles`, `orders`, `payments`, `invoices`, `messages`, `uploads`, `files`, and `documents`. These are candidate paths only. A finding is emitted only when the REST endpoint returns access evidence, for example HTTP `200` with `documents[]` or root collection IDs.

AizaScope also exposes the candidate set through:

```bash
aizascope --show-probe-wordlists
```

## Realtime Database

- `GET https://{PROJECT}.firebaseio.com/.json?shallow=true&timeout=3s`
- `GET https://{PROJECT}-default-rtdb.firebaseio.com/.json?shallow=true&timeout=3s`
- marker `PUT`/`DELETE` only after read proof

## Firebase Storage

- `GET https://firebasestorage.googleapis.com/v0/b/{BUCKET}/o?maxResults=1`
- `GET https://firebasestorage.googleapis.com/v0/b/{BUCKET}/o?prefix={PREFIX}&maxResults=1`
- candidate buckets: config bucket, `{PROJECT}.appspot.com`, `{PROJECT}.firebasestorage.app`
- marker upload/delete only after list proof

## Gemini / Generative Language API

- `GET https://generativelanguage.googleapis.com/v1beta/models?key={KEY}`
- `GET https://generativelanguage.googleapis.com/v1beta/files?pageSize=1&key={KEY}`
- `GET https://generativelanguage.googleapis.com/v1beta/cachedContents?pageSize=1&key={KEY}`
- `GET https://generativelanguage.googleapis.com/v1beta/batches?pageSize=1&key={KEY}`
- `POST https://generativelanguage.googleapis.com/v1beta/models/{MODEL}:countTokens?key={KEY}`
- `POST https://generativelanguage.googleapis.com/v1beta/models/{MODEL}:generateContent?key={KEY}`
- `POST https://generativelanguage.googleapis.com/v1beta/models/{MODEL}:embedContent?key={KEY}`

## YouTube Data API

- `videos.list`
- `channels.list`
- `commentThreads.list`
- `playlists.list`
- `playlistItems.list`
- `activities.list`
- `subscriptions.list`
- `channelSections.list`
- `search.list` expensive proof
- OAuth/content-owner negative controls: `managedByMe=true`, `videos.rate`

## Maps Platform

- Maps JavaScript API loader
- Geocoding API
- Static Maps API
- Places Legacy Text Search
- Places New Text Search
- Directions API
- Distance Matrix API
- Time Zone API
- Geolocation API

## Cloud AI APIs

- Cloud Vision `images.annotate`
- Cloud Translation Basic `detect`
- Cloud Natural Language `documents:analyzeSentiment`

## Safe Browsing

- `POST https://safebrowsing.googleapis.com/v4/threatMatches:find?key={KEY}`

## Discovery metadata

- `GET https://www.googleapis.com/discovery/v1/apis`



## Write proof is opt-in

AizaScope does not perform marker writes by default. Firestore, RTDB, and Storage marker write/delete endpoints are used only when `--prove-write` is explicitly supplied and only after read/list exposure is already confirmed.


## YouTube quota wording

AizaScope treats YouTube Data API public endpoints as quota/API-restriction exposure. Current YouTube documentation states that every request costs at least one quota point and that `search.list` has a separate limited default allocation. The tool does not claim private YouTube data access from public-data endpoints.
