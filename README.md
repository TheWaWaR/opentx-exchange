# Prove of concept open transaction based exchange client/server

## Usage
```
Usage: opentx-exchange <COMMAND>

Commands:
  gen-order                Generate and sign an order transaction (partial open transaction)
  merge-orders             Merge multiple order transactions into one transaction
  issue-udt                Issue some xUDT amount to address
  new-empty-udt-cell       Create new empty xUDT cell
  cancel-order             Cancel an order transaction by use one of the input cell in it
  build-omni-lock-address  Build open transaction compatible omni-lock address
  send-to-exchange         Send the order transaction to exchange
  query-order-by-address   Query orders by the omni-lock address
  query-order-by-sell      Query orders by the sell information
  query-order-by-buy       Query orders by the buy information
  gen-example-cell-deps    Generate example cell_deps.json
  start-exchange           Start exchange jsonrpc server
  help                     Print this message or the help of the given subcommand(s)
```
