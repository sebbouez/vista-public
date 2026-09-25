The store for stencils collections to use in Vista.

## Adding a stencils collection

1. Add a `manifest.json` file at the root of the collection ZIP file:

```json
{
  "internalId": "my-collection",
  "displayName": "My collection",
  "version": "1.0.0"
}
```

| Field | Description |
|---|---|
| `internalId` | Unique and stable identifier of the collection. Must match the `id` declared in `index.json`. |
| `displayName` | Name displayed in Vista's shapes library. |
| `version` | Version of the collection (`major.minor[.build]`). |

2. Put the collection ZIP file in this folder.
3. Declare it in the `stencils` array of the `index.json` file at the root of the repository:

```json
{
  "id": "my-collection",
  "name": "My collection",
  "description": "Short description of the collection.",
  "file": "stencils/my collection.zip",
  "version": "1.0.0",
  "shapesCount": 42,
  "size": 123456,
  "sourceUrl": "https://example.com/icons"
}
```

| Field | Required | Description |
|---|---|---|
| `id` | yes | Unique identifier of the collection, same as `internalId` in the manifest. |
| `name` | yes | Name displayed in the stencils library manager. |
| `description` | no | Short description. |
| `file` | yes | Path of the ZIP file, relative to the repository root. |
| `version` | no | Published version, same as `version` in the manifest. |
| `shapesCount` | no | Number of shapes in the collection. |
| `size` | no | Size of the ZIP file, in bytes. |
| `sourceUrl` | no | Origin of the icons and their terms of use. |

## Publishing an update

Increase `version` both in the ZIP `manifest.json` and in `index.json`. Vista offers the update when the published version is newer than the installed one.
