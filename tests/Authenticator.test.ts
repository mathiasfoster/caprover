import bcrypt = require('bcryptjs')
import Authenticator from '../src/user/Authenticator'
import CaptainConstants from '../src/utils/CaptainConstants'

test('Testing Authenticator 1', () => {
    const passwordStored =
        '5EXJbB3Ys4fSg8M7m8FFt8duVvej9oD93SfgXjNNn6EbXG9KU63CZhZbRZ79amRw'
    // const passwordEntered =
    //     '5EXJbB3Ys4fSg8M7m8FFt8duVvej9oD93SfgXjNNnaaaaaaaaaaaaaaaaaaaaaaaaaa6EbXG9KU63CZhZbRZ79amRw'
    const HASH = '2848d8c9-4719-4ad1-bc12-c405a78913c5captain'

    let hashed = bcrypt.hashSync(HASH + passwordStored, bcrypt.genSaltSync(10))

    hashed = '$2a$10$9pEXSGfCSiz/ZC49ucqHuOCiuCy2dK17uqQtXn8BQfx2jt8cYFA9K'

    expect(
        bcrypt.compareSync(
            HASH +
                '5EXJbB3Ys4fSg8M7m8FFt8duVvej9oD93SfgXjNNnaaaaaaaaaaaaaaaaaaaaaaaaaa6EbXG9KU63CZhZbRZ79amRw',
            hashed
        )
    ).toBe(true)
})

describe('Authenticator tokenVersion persistence', () => {
    beforeAll(() => {
        // setMainSalt throws if called twice; safe to call once per test file
        // since jest runs each file in its own worker process.
        Authenticator.setMainSalt(
            'unit-test-salt-not-used-anywhere-real-1234567890'
        )
    })

    test('getTokenVersion returns a non-empty value out of the box', () => {
        const auth = Authenticator.getAuthenticator(
            CaptainConstants.rootNameSpace
        )
        expect(typeof auth.getTokenVersion()).toBe('string')
        expect(auth.getTokenVersion().length).toBeGreaterThan(0)
    })

    test('setTokenVersion overrides the in-memory version (restart hydration)', () => {
        const auth = Authenticator.getAuthenticator(
            CaptainConstants.rootNameSpace
        )
        const persisted = 'persisted-token-version-from-disk'
        auth.setTokenVersion(persisted)
        expect(auth.getTokenVersion()).toBe(persisted)
    })

    test('setTokenVersion rejects empty values', () => {
        const auth = Authenticator.getAuthenticator(
            CaptainConstants.rootNameSpace
        )
        expect(() => auth.setTokenVersion('')).toThrow()
    })

    test('a token issued with the persisted version still decodes after a simulated restart', async () => {
        const auth = Authenticator.getAuthenticator(
            CaptainConstants.rootNameSpace
        )
        const stableVersion = 'stable-version-across-restarts'
        auth.setTokenVersion(stableVersion)

        const token = await auth.getAuthToken(
            {
                otpToken: '',
                otpAuthenticator: {
                    isOtpTokenValid: () => Promise.resolve(true),
                },
            },
            'captain42',
            ''
        )

        // Simulate a process restart: a new in-memory tokenVersion is
        // generated, then the persisted value is rehydrated from the data
        // store. Because the hydrated value matches what the JWT carries, the
        // token must still verify.
        auth.setTokenVersion('something-else-from-fresh-startup')
        auth.setTokenVersion(stableVersion)

        const decoded = await auth.decodeAuthToken(token)
        expect(decoded.namespace).toBe(CaptainConstants.rootNameSpace)
        expect(decoded.tokenVersion).toBe(stableVersion)
    })
})
