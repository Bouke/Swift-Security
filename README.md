# Swift-Security

Package for typed access to Security (Keychain) services. I built this over the weekend to check how hard it would be to block root certificates, using Swift.

When included as a framework, import it as any other framework:

```swift
import Swift_Security
```

To list all installed root certificates:

```swift
let certificates = root_certs()
println(certificates)
```

Some basic info can be listed about the certificate as well:

```swift
certificates[0].commonName
certificates[0].subjectCountry
```

Check the trust settings for a certificate.

```swift
let nl = first(certificates.filter { $0.subjectCountry == "NL" })
println(nl?.commonName)
println(nl?.trustSettings(.Admin))
```

Change the trust setting for a certificate. This doesn't work in a playground, as a UI dialog for confirming this action will be spawned by OS X.

```swift
if var trust = nl?.trustSettings(.Admin) {
    trust[.AppleSSL] = .Deny
    println(trust.save())
}
```
