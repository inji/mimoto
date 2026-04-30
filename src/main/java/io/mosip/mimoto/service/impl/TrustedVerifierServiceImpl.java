package io.mosip.mimoto.service.impl;

import io.mosip.mimoto.dto.TrustedVerifierRequest;
import io.mosip.mimoto.dto.TrustedVerifierResponseDTO;
import io.mosip.mimoto.exception.InvalidRequestException;
import io.mosip.mimoto.model.TrustedVerifier;
import io.mosip.mimoto.repository.VerifierRepository;
import io.mosip.mimoto.service.TrustedVerifierService;
import org.springframework.stereotype.Service;

import java.util.UUID;

import static io.mosip.mimoto.exception.ErrorConstants.*;

@Service
public class TrustedVerifierServiceImpl implements TrustedVerifierService {

    private final VerifierRepository verifierRepository;

    public TrustedVerifierServiceImpl(VerifierRepository verifierRepository) {
        this.verifierRepository = verifierRepository;
    }

    @Override
    public TrustedVerifierResponseDTO addTrustedVerifier(String walletId, TrustedVerifierRequest trustedVerifierRequest) {
        // Check if already exists to avoid duplicates
        if (verifierRepository.existsByWalletIdAndVerifierId(walletId, trustedVerifierRequest.getVerifierId())) {
            throw new InvalidRequestException(DUPLICATE_VERIFIER.getErrorCode(), DUPLICATE_VERIFIER.getErrorMessage());
        }

        TrustedVerifier trustedVerifier = TrustedVerifier.builder()
                .id(UUID.randomUUID().toString())  // Generate unique ID
                .walletId(walletId)
                .verifierId(trustedVerifierRequest.getVerifierId())
                .build();

        TrustedVerifier row = verifierRepository.save(trustedVerifier);

        TrustedVerifierResponseDTO trustedVerifierResponseDTO = new TrustedVerifierResponseDTO();
        trustedVerifierResponseDTO.setId(row.getId());
        return trustedVerifierResponseDTO;
    }
}