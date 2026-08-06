import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

// SE-4: the LICENSE text and the package.json license field drifted apart (AGPL vs MIT), so SCA
// tooling in the proprietary consumer apps read a permissive grant the repo never made. These
// assertions pin the two together so the metadata cannot silently go stale again.
const read = (name: string) => readFileSync(fileURLToPath(new URL(name, import.meta.url)), 'utf-8')

describe('license metadata', () => {
    const pkg = JSON.parse(read('./package.json')) as { license: string }
    const licenseText = read('./LICENSE')

    it('LICENSE is the GNU Affero GPL v3 text', () => {
        expect(licenseText).toContain('GNU AFFERO GENERAL PUBLIC LICENSE')
        expect(licenseText).toContain('Version 3, 19 November 2007')
    })

    it('package.json declares the SPDX id matching that text', () => {
        // "-only", not "-or-later": the project makes no "or any later version" grant. The only
        // such wording in LICENSE sits in the FSF's "How to Apply These Terms" appendix, which is
        // instructions for authors, not this project's grant, and no source file carries a header.
        expect(pkg.license).toBe('AGPL-3.0-only')
    })
})
