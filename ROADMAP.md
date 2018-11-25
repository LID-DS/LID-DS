# LID-DS

## Package

- Stage 1 (Init from old state)
- Stage 2 (Cleanup )
- Stage 3 (Tentative)
    - tests
    - are more complete set of event-distribution functions
    - a more stable approach to recording
    - fetch live stream data from recording containers
    - generator for normal behavior data
    - provide repositories of security related information like:
        * bad passwords
        * good passwords
        * wordlists
        * url crawl lists
        * user data generator
        * content data generator
    - real-world-like network configurations for victim and attacker containers (packet-loss; latency)
        * more research on this is neccessary
        * but can easily be done on linux via tc
    - we probably should implement our own recording system since sysdig only works on linux the way we need it to work
