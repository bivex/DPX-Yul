object "YulVault" {
    code {
        // Deploy constructor: copy runtime code to memory and return
        datacopy(0, dataoffset("YulVault_deployed"), datasize("YulVault_deployed"))
        return(0, datasize("YulVault_deployed"))
    }
    object "YulVault_deployed" {
        code {
            // Function selector dispatcher
            switch shr(224, calldataload(0))
            case 0xd0e30db0 {
                // deposit()
                deposit()
            }
            case 0x2e1a7d4d {
                // withdraw(uint256)
                withdraw(calldataload(4))
            }
            case 0x70a08231 {
                // balanceOf(address)
                balanceOf(calldataload(4))
            }
            default {
                revert_custom_error(0xfb8f38b2) // InvalidSelector()
            }

            function deposit() {
                // Reentrancy lock using Transient Storage (EIP-1153)
                if tload(0x00) {
                    revert_custom_error(0xab143c06) // Reentrancy()
                }
                tstore(0x00, 1)

                let user := caller()
                let amount := callvalue()
                let slot := derive_balance_slot(user)
                let current_bal := sload(slot)
                sstore(slot, add(current_bal, amount))

                // Emit Transfer / Deposit log
                mstore(0x00, amount)
                log3(0x00, 0x20, 0xddf252ad1be2c89b69c2b068fc378d579fb83fbf, 0, user)

                tstore(0x00, 0)
            }

            function withdraw(amount) {
                if tload(0x00) {
                    revert_custom_error(0xab143c06)
                }
                tstore(0x00, 1)

                let user := caller()
                let slot := derive_balance_slot(user)
                let current_bal := sload(slot)
                if lt(current_bal, amount) {
                    revert_custom_error(0x19213894) // InsufficientFunds()
                }
                sstore(slot, sub(current_bal, amount))

                // Low level transfer
                let ok := call(gas(), user, amount, 0, 0, 0, 0)
                if iszero(ok) {
                    revert_custom_error(0x90b8ec18) // TransferFailed()
                }

                tstore(0x00, 0)
            }

            function balanceOf(user) {
                let slot := derive_balance_slot(user)
                let bal := sload(slot)
                let ptr := mload(0x40)
                mstore(ptr, bal)
                return(ptr, 0x20)
            }

            function derive_balance_slot(user) -> slot {
                mstore(0x00, user)
                mstore(0x20, 0x01)
                slot := keccak256(0x00, 0x40)
            }

            function revert_custom_error(selector) {
                mstore(0x00, selector)
                revert(0x1c, 0x24)
            }
        }
    }
}
