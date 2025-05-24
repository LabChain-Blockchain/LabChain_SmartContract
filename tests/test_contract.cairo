#[cfg(test)]
mod test {
    use super::*;
    use snforge_std::{
        ContractClassTrait, DeclareResultTrait, declare, spy_events,
        EventSpyAssertionsTrait, start_cheat_caller_address_global,
        stop_cheat_caller_address_global, load
    };
    use crate::LabChain::{ILabCertsDispatcher, ILabCertsDispatcherTrait, Event};

    fn deploy() -> ILabCertsDispatcher {
        let contract = declare("LabChain").unwrap().contract_class();
        let (contract_address, _) = contract.deploy(@array![]).unwrap();
        ILabCertsDispatcher { contract_address }
    }

    #[test]
    fn test_mint_and_verify_cert() {
        let caller = starknet::contract_address_const::<'caller'>();
        start_cheat_caller_address_global(caller);

        let contract = deploy();
        let cert_hash: felt252 = 'cert001';
        let proof = array![1, 2, 3];
        let timestamp: felt252 = 123456;

        contract.mint_cert(caller, cert_hash, proof.span(), timestamp);

        // Verificación de evento emitido
        let mut spy = spy_events();
        contract.mint_cert(caller, cert_hash, proof.span(), timestamp);

        spy.assert_emitted(
            @array![
                (
                    contract.contract_address,
                    Event::CertificateMinted(crate::LabChain::LabEvents::CertificateMinted {
                        token_id: 0,
                        to: caller,
                        cert_hash
                    })
                )
            ]
        );

        let is_valid = contract.verify_cert(cert_hash, proof.span());
        assert_eq!(is_valid, 1);
    }

    #[test]
    #[should_panic]
    fn test_duplicate_cert_should_fail() {
        let caller = starknet::contract_address_const::<'caller'>();
        start_cheat_caller_address_global(caller);

        let contract = deploy();
        let cert_hash: felt252 = 'cert001';
        let proof = array![1, 2, 3];
        let timestamp: felt252 = 123456;

        contract.mint_cert(caller, cert_hash, proof.span(), timestamp);
        // Should panic here
        contract.mint_cert(caller, cert_hash, proof.span(), timestamp);
    }

    #[test]
    #[should_panic]
    fn test_unauthorized_lab_should_fail() {
        let owner = starknet::contract_address_const::<'owner'>();
        start_cheat_caller_address_global(owner);
        let contract = deploy();
        stop_cheat_caller_address_global();

        let not_owner = starknet::contract_address_const::<'not_owner'>();
        start_cheat_caller_address_global(not_owner);

        let cert_hash: felt252 = 'unauth';
        let proof = array![9, 9, 9];
        let timestamp: felt252 = 111111;

        // Should panic due to unauthorized access
        contract.mint_cert(not_owner, cert_hash, proof.span(), timestamp);
    }
}