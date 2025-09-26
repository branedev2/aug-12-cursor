// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=0}
// ok:detect-buffer-noassert
a.readUInt8(0)
// {/fact}

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=0}
// ok:detect-buffer-noassert
a.readUInt8(0, false)
// {/fact}

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=1}
// ruleid:detect-buffer-noassert
a.readUInt8(0, true)
// {/fact}

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=1}
// ruleid:detect-buffer-noassert
a.writeFloatLE(0, true)
// {/fact}