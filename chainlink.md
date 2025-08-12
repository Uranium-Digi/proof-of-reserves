chainlink_solana_data_streams = { git = "https://github.com/smartcontractkit/chainlink-data-streams-solana", subdir = "crates/chainlink-solana-data-streams" ,tag = "v1.1.0"}

https://github.com/smartcontractkit/chainlink-data-streams-solana/tree/893d2340254935fb947c95b6aa8e9e245c65ddc4

https://docs.google.com/document/d/1FcZ4r-Y7dckzD47isfwO0C4FohEthAeaDidXSgxtQWY/edit?usp=sharing

https://docs.chain.link/data-streams/tutorials/solana-onchain-report-verification

V9 Schema Field | Mapping | Description for Your Integration
aum | totalReserve | The total value of your segregated reserves for the specific chain. This is the primary value your on-chain program will consume.
ripcord
ripcord
A boolean flag (0 for normal, 1 for paused) indicating if there is an issue with the reserve data. Your program should always check this before consuming the aum value.
navDate
timestamp
The UNIX timestamp of when the reserve data was reported by your custodian.
navPerShare
N/A (Set to 0)
