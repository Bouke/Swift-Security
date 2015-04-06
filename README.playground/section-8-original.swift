let nl = first(certificates.filter { $0.subjectCountry == "NL" })
println(nl?.commonName)
println(nl?.trustSettings(.Admin))
