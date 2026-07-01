package io.mosip.mimoto.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.constant.CredentialFormat;
import io.mosip.mimoto.dto.DecryptedCredentialDTO;
import io.mosip.mimoto.dto.mimoto.VCCredentialProperties;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import io.mosip.openID4VP.constants.FormatType;
import io.mosip.openID4VP.dcql.evaluator.ClaimFailure;
import io.mosip.openID4VP.dcql.evaluator.QueryMatchResult;
import io.mosip.openID4VP.dcql.query.CredentialQuery;
import io.mosip.openID4VP.dcql.query.DCQLQuery;
import io.mosip.openID4VP.wallet.Credential;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Maps mimoto wallet credentials for inji-openid4vp {@link io.mosip.openID4VP.helper.DCQLHelper}
 * evaluation and derives UI missing-claim hints from library match results.
 */
public final class DcqlMatchingHelper {

    private DcqlMatchingHelper() {
    }

    public static DCQLQuery normalizeDcqlQuery(DCQLQuery dcqlQuery) {
        List<CredentialQuery> credentials = dcqlQuery.getCredentials().stream()
                .map(DcqlMatchingHelper::normalizeCredentialQuery)
                .collect(Collectors.toList());
        return new DCQLQuery(credentials, dcqlQuery.getCredentialSets());
    }

    public static List<Credential> toLibraryCredentials(
            List<DecryptedCredentialDTO> decryptedCredentials,
            ObjectMapper objectMapper) {
        List<Credential> libraryCredentials = new ArrayList<>();
        for (DecryptedCredentialDTO dto : decryptedCredentials) {
            Credential mapped = toLibraryCredential(dto, objectMapper);
            if (mapped == null) {
                continue;
            }
            libraryCredentials.add(mapped);
            FormatType alternateFormat = alternateSdJwtFormat(mapped.getFormat());
            if (alternateFormat != null) {
                libraryCredentials.add(new Credential(alternateFormat, mapped.getData(), mapped.getCredentialId()));
            }
        }
        return libraryCredentials;
    }

    public static Credential toLibraryCredential(DecryptedCredentialDTO dto, ObjectMapper objectMapper) {
        VCCredentialResponse vc = dto.getCredential();
        if (vc == null) {
            return null;
        }
        String format = vc.getFormat();
        Object credentialData = vc.getCredential();
        if (format == null || credentialData == null) {
            return null;
        }

        if (CredentialFormat.isSdJwt(format)) {
            String sdJwt = asSdJwtString(credentialData, objectMapper);
            if (sdJwt == null) {
                return null;
            }
            FormatType formatType = mapToFormatType(format);
            if (formatType == null) {
                return null;
            }
            return new Credential(formatType, sdJwt, dto.getId());
        }

        if (CredentialFormat.LDP_VC.getFormat().equalsIgnoreCase(format)) {
            Map<String, Object> credentialMap = asCredentialMap(credentialData, objectMapper);
            if (credentialMap == null) {
                return null;
            }
            return new Credential(FormatType.LDP_VC, credentialMap, dto.getId());
        }

        return null;
    }

    public static Set<String> resolveMissingClaims(CredentialQuery credentialQuery, QueryMatchResult queryMatch) {
        if (queryMatch != null && queryMatch.getFailedClaims() != null && !queryMatch.getFailedClaims().isEmpty()) {
            return queryMatch.getFailedClaims().stream()
                    .map(ClaimFailure::getClaim)
                    .filter(Objects::nonNull)
                    .map(claim -> DcqlClaimSetHelper.buildClaimPath(claim.getPath()))
                    .collect(Collectors.toCollection(LinkedHashSet::new));
        }
        return extractMissingClaimsFromQuery(credentialQuery);
    }

    private static Set<String> extractMissingClaimsFromQuery(CredentialQuery credentialQuery) {
        if (credentialQuery.getClaims() == null) {
            return Set.of();
        }
        if (DcqlClaimSetHelper.hasClaimSets(credentialQuery)) {
            return credentialQuery.getClaimSets().stream()
                    .flatMap(claimIds -> DcqlClaimSetHelper.pathsForClaimIds(credentialQuery, claimIds).stream())
                    .collect(Collectors.toCollection(LinkedHashSet::new));
        }
        return credentialQuery.getClaims().stream()
                .filter(cq -> cq.getPath() != null && !cq.getPath().isEmpty())
                .map(cq -> DcqlClaimSetHelper.buildClaimPath(cq.getPath()))
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    private static CredentialQuery normalizeCredentialQuery(CredentialQuery query) {
        Map<String, Object> meta = query.getMeta();
        if (meta != null) {
            return query;
        }
        return new CredentialQuery(
                query.getId(),
                query.getFormat(),
                query.getMultiple(),
                Map.of(),
                query.getRequireCryptographicHolderBinding(),
                query.getClaims(),
                query.getClaimSets());
    }

    private static FormatType alternateSdJwtFormat(FormatType format) {
        if (format == FormatType.VC_SD_JWT) {
            return FormatType.DC_SD_JWT;
        }
        if (format == FormatType.DC_SD_JWT) {
            return FormatType.VC_SD_JWT;
        }
        return null;
    }

    private static String asSdJwtString(Object credentialData, ObjectMapper objectMapper) {
        if (credentialData instanceof String sdJwt) {
            return sdJwt.isBlank() ? null : sdJwt;
        }
        return null;
    }

    private static FormatType mapToFormatType(String format) {
        if (CredentialFormat.LDP_VC.getFormat().equalsIgnoreCase(format)) {
            return FormatType.LDP_VC;
        }
        if (CredentialFormat.VC_SD_JWT.getFormat().equalsIgnoreCase(format)) {
            return FormatType.VC_SD_JWT;
        }
        if (CredentialFormat.DC_SD_JWT.getFormat().equalsIgnoreCase(format)) {
            return FormatType.DC_SD_JWT;
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asCredentialMap(Object credentialData, ObjectMapper objectMapper) {
        if (credentialData instanceof Map<?, ?> rawMap) {
            Map<String, Object> credentialMap = new LinkedHashMap<>();
            for (Map.Entry<?, ?> entry : rawMap.entrySet()) {
                if (entry.getKey() instanceof String key) {
                    credentialMap.put(key, entry.getValue());
                }
            }
            return credentialMap;
        }
        if (credentialData instanceof VCCredentialProperties properties) {
            return objectMapper.convertValue(properties, Map.class);
        }
        return null;
    }
}
