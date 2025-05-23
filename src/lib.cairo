/// LabChain - Certificados NFT con validación ZK, revocación y metadatos
#[starknet::interface]
trait ILabCerts<TContractState> {
    /// Emite un nuevo certificado NFT si el laboratorio está autorizado y el hash es único.
    fn mint_cert(
        ref self: TContractState,
        to: ContractAddress,
        cert_hash: felt252,
        zk_proof: Span<felt252>,
        timestamp: felt252,
    );

    /// Verifica un certificado NFT usando la prueba ZK proporcionada.
    fn verify_cert(
        self: @TContractState,
        cert_hash: felt252,
        zk_proof: Span<felt252>,
    ) -> felt252;

    /// Revoca un certificado NFT, haciendo que pierda validez futura.
    fn revoke_cert(ref self: TContractState, cert_hash: felt252);
}

#[starknet::contract]
mod LabChain {
    use starknet::{get_caller_address, ContractAddress};
    use starknet::storage::{LegacyMap, StoragePointerReadAccess, StoragePointerWriteAccess};
    use core::traits::Zero;

    /// Definición de eventos emitidos por el contrato.
    mod LabEvents {
        #[derive(Copy, Drop, Debug, PartialEq, starknet::Event)]
        pub struct CertificateMinted {
            #[key]
            pub token_id: u256,
            #[key]
            pub to: starknet::ContractAddress,
            pub cert_hash: felt252,
        }

        #[derive(Copy, Drop, Debug, PartialEq, starknet::Event)]
        pub struct CertificateVerified {
            #[key]
            pub cert_hash: felt252,
            pub is_valid: bool,
        }

        #[derive(Copy, Drop, Debug, PartialEq, starknet::Event)]
        pub struct CertificateRevoked {
            #[key]
            pub cert_hash: felt252,
        }
    }

    /// Códigos de error comunes utilizados en las validaciones del contrato.
    mod Errors {
        pub const UNAUTHORIZED: felt252 = 'caller_not_authorized';
        pub const INVALID_PROOF: felt252 = 'zk_proof_invalid';
        pub const EMPTY_HASH: felt252 = 'cert_hash_cannot_be_zero';
        pub const DUPLICATE: felt252 = 'duplicate_cert';
        pub const EXPIRED: felt252 = 'cert_expired';
        pub const REVOKED: felt252 = 'cert_revoked';
    }

    /// Estructura del certificado almacenado.
    #[derive(Drop, Serde, Copy, starknet::Store)]
    struct Certificate {
        cert_hash: felt252,
        timestamp: felt252,
        issuer: ContractAddress,
        revoked: bool,
    }

    /// Estructura de almacenamiento del contrato.
    #[storage]
    struct Storage {
        owner: ContractAddress,                      // Dueño del contrato
        next_token_id: u256,                        // Contador incremental de IDs
        authorized_labs: LegacyMap<ContractAddress, bool>, // Laboratorios autorizados
        certs_by_hash: LegacyMap<felt252, Certificate>,     // Certificados por hash
        cert_owner: LegacyMap<felt252, ContractAddress>,    // Dueño del certificado
    }

    /// Eventos expuestos externamente.
    #[event]
    #[derive(Copy, Drop, Debug, PartialEq, starknet::Event)]
    pub enum Event {
        CertificateMinted: LabEvents::CertificateMinted,
        CertificateVerified: LabEvents::CertificateVerified,
        CertificateRevoked: LabEvents::CertificateRevoked,
    }

    /// Constructor que establece al dueño y reinicia el contador de certificados.
    #[constructor]
    fn constructor(ref self: ContractState) {
        let deployer = get_caller_address();
        self.owner.write(deployer);
        self.next_token_id.write(0);
    }

    #[abi(embed_v0)]
    impl LabCertsImpl of ILabCerts<ContractState> {
        /// Emite un certificado NFT si cumple validaciones básicas y de autorización.
        fn mint_cert(
            ref self: ContractState,
            to: ContractAddress,
            cert_hash: felt252,
            zk_proof: Span<felt252>,
            timestamp: felt252,
        ) {
            assert(cert_hash != 0, Errors::EMPTY_HASH);
            assert(zk_proof.len() > 0, Errors::INVALID_PROOF);

            let caller = get_caller_address();
            assert(self.authorized_labs.read(caller), Errors::UNAUTHORIZED);
            assert(self.certs_by_hash.read(cert_hash).issuer.is_zero(), Errors::DUPLICATE);

            let cert = Certificate {
                cert_hash,
                timestamp,
                issuer: caller,
                revoked: false,
            };
            self.certs_by_hash.write(cert_hash, cert);
            self.cert_owner.write(cert_hash, to);

            let token_id = self.next_token_id.read();
            self.next_token_id.write(token_id + 1);

            self.emit(Event::CertificateMinted(LabEvents::CertificateMinted {
                token_id,
                to,
                cert_hash,
            }));
        }

        /// Verifica un certificado NFT con una prueba ZK (placeholder).
        fn verify_cert(self: @ContractState, cert_hash: felt252, zk_proof: Span<felt252>) -> felt252 {
            let cert = self.certs_by_hash.read(cert_hash);
            assert(!cert.revoked, Errors::REVOKED);
            assert(zk_proof.len() > 0, Errors::INVALID_PROOF); // Validación simbólica

            self.emit(Event::CertificateVerified(LabEvents::CertificateVerified {
                cert_hash,
                is_valid: true,
            }));

            1 // Retorna 1 si es válido
        }

        /// Revoca un certificado si es el dueño o el emisor original.
        fn revoke_cert(ref self: ContractState, cert_hash: felt252) {
            let caller = get_caller_address();
            let cert = self.certs_by_hash.read(cert_hash);
            assert(caller == self.owner.read() || caller == cert.issuer, Errors::UNAUTHORIZED);

            let mut updated_cert = cert;
            updated_cert.revoked = true;
            self.certs_by_hash.write(cert_hash, updated_cert);

            self.emit(Event::CertificateRevoked(LabEvents::CertificateRevoked {
                cert_hash,
            }));
        }
    }
}