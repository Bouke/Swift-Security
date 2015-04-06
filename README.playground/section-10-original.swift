if var trust = nl?.trustSettings(.Admin) {
    trust[.AppleSSL] = .Deny
    println(trust.save())
}
