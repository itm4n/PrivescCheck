@{
    Severity = @(
        "Error",
        "Warning",
        "Information"
    )

    ExcludeRules = @(
        "PSUseShouldProcessForStateChangingFunctions",
        "PSAvoidUsingWMICmdlet", # Get-WmiObject is required for PSv2 retro-compatibility
        "PSAvoidUsingBrokenHashAlgorithms" # MD5 and SHA1 required for identifying known vulnerable drivers
    )
}