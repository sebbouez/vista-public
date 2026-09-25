# Contributing

Thank you for contributing shape libraries to Vista!

Vista downloads the libraries straight from the `main` branch: once a pull request is merged,
it is available to every Vista user. That is why every pull request is validated automatically,
then reviewed by a maintainer.

## Submitting a library

1. Fork the repository.
2. Add or update the ZIP file in the `stencils/` folder and declare it in `index.json`
   (see [stencils/readme.md](stencils/readme.md) for the formats).
3. Run the validation locally (Python 3, no dependency needed):

   ```bash
   python3 .github/scripts/validate_stencils.py --base origin/main
   ```

4. Open a pull request. The **Validate stencil libraries** check must pass before review.

## What the validation checks

**Index**
- `id` is unique and made of lowercase letters, digits and dashes.
- `file` is a `.zip` file directly in the `stencils/` folder, and exists.
- `version` is required (`1.0` or `1.0.0`).
- `size` and `shapesCount`, when present, match the ZIP file.
- `sourceUrl`, when present, is an `https://` address.

**Archive**
- All files are at the root of the archive: no folder, no relative or absolute path.
- Only `manifest.json`, `.xml` stencils and `.md` notes (such as a license) are accepted.
- Size limits: 20 MB per archive, 1 MB per file, 50 MB uncompressed, no suspicious compression ratio.
- No encrypted file.
- `manifest.json` is present, and its `internalId` and `version` match `id` and `version` in `index.json`.

**Stencils**
- Each `.xml` file is well-formed UTF-8 XML with a `<Stencil>` root, a `<Name>` and an `<Svg>`.
  Remember to escape `&`, `<` and `>` in names and descriptions.
- No `DOCTYPE` or `ENTITY` declaration.

**SVG security**
- Only drawing elements are allowed: shapes, text, groups, gradients, patterns, masks, clip paths and simple filters.
  `<script>`, `<foreignObject>`, `<image>`, `<a>`, animations and any other element are rejected.
- No event handler attribute (`onload`, `onclick`...).
- No external resource: `href` and CSS `url()` may only reference an element of the same SVG (`#id`).
- No `@import`, `expression()` or `javascript:` in styles.

## Updating a library

Any change to the content of a ZIP file requires a new version: increase `version` both in the
`manifest.json` of the archive and in `index.json`. Vista offers the update to users who installed
a previous version.

## Reviewing a pull request

The run summary of the **Validate stencil libraries** check lists, for each library, the shapes that
were added, modified or removed. The **stencils-preview** artifact of the run contains an HTML page
displaying these shapes, to review them visually.
