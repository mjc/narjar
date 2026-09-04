# Offline GC scale measurement

The ignored `gc_scale` integration test created deterministic fixtures with 0,
100, 1,000, and 10,000 signed published paths sharing one NAR. For each fixture
it measured a no-selection inventory pass, a target-zero dry run, and a
target-zero apply pass using the optimized release binary. Raw samples and the
exact environment are adjacent.

At 10,000 paths, inventory took 777.625 ms, the dry run took 780.991 ms, and
peak RSS was 9,088 KiB. Apply took 37,371.121 ms because it preserves the
durability contract by syncing the cache directory after every narinfo unlink;
this is offline maintenance, not a serving-path operation.
