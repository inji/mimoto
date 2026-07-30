package io.mosip.mimoto.service;

import com.authlete.sd.Disclosure;
import com.authlete.sd.SDJWT;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.itextpdf.html2pdf.ConverterProperties;
import com.itextpdf.html2pdf.HtmlConverter;
import com.itextpdf.html2pdf.resolver.font.DefaultFontProvider;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.nimbusds.jose.util.Base64URL;
import io.mosip.injivcrenderer.InjiVcRenderer;
import io.mosip.mimoto.constant.CredentialFormat;
import io.mosip.mimoto.constant.LdpVcV1Constants;
import io.mosip.mimoto.constant.LdpVcV2Constants;
import io.mosip.mimoto.constant.SdJwtVcConstants;
import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.mimoto.CredentialIssuerDisplayResponse;
import io.mosip.mimoto.dto.mimoto.CredentialSupportedDisplayResponse;
import io.mosip.mimoto.dto.mimoto.CredentialsSupportedResponse;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import io.mosip.mimoto.dto.openid.presentation.PresentationDefinitionDTO;
import io.mosip.mimoto.model.QRCodeType;
import io.mosip.mimoto.service.impl.PresentationServiceImpl;
import io.mosip.mimoto.util.LocaleUtils;
import io.mosip.mimoto.util.SvgFixerUtil;
import io.mosip.mimoto.util.Utilities;
import io.mosip.pixelpass.PixelPass;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections.CollectionUtils;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.Velocity;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Slf4j
@Service
public class CredentialPDFGeneratorService {

    private record SelectedFace(String key, String face) {}

    private final ObjectMapper objectMapper;

    private final PresentationServiceImpl presentationService;

    private final Utilities utilities;

    private final PixelPass pixelPass;

    private final CredentialFormatHandlerFactory credentialFormatHandlerFactory;

    private final InjiVcRenderer injiVcRenderer;

    private final SvgFixerUtil svgFixerUtil;

    public CredentialPDFGeneratorService(ObjectMapper objectMapper, PresentationServiceImpl presentationService, Utilities utilities, PixelPass pixelPass, CredentialFormatHandlerFactory credentialFormatHandlerFactory, InjiVcRenderer injiVcRenderer, SvgFixerUtil svgFixerUtil) {
        this.objectMapper = objectMapper;
        this.presentationService = presentationService;
        this.utilities = utilities;
        this.pixelPass = pixelPass;
        this.credentialFormatHandlerFactory = credentialFormatHandlerFactory;
        this.injiVcRenderer = injiVcRenderer;
        this.svgFixerUtil = svgFixerUtil;
    }

    @Value("${mosip.inji.ovp.qrdata.pattern}")
    private String ovpQRDataPattern;

    @Value("${mosip.inji.qr.code.height:500}")
    Integer qrCodeHeight;

    @Value("${mosip.inji.qr.code.width:500}")
    Integer qrCodeWidth;

    @Value("${mosip.inji.qr.data.size.limit:4096}")
    Integer allowedQRDataSizeLimit;

    @Value("${mosip.injiweb.vc.subject.face.keys.order:image,face,photo,picture,portrait}")
    private String faceImageLookupKeys;

    @Value("${mosip.injiweb.mask.disclosures:true}")
    private boolean maskDisclosures;

    private static final String CLAIM_169_KEY = "claim169";
    
    public ByteArrayInputStream generatePdfForVerifiableCredential(String credentialConfigurationId, VCCredentialResponse vcCredentialResponse, IssuerDTO issuerDTO, CredentialsSupportedResponse credentialsSupportedResponse, String dataShareUrl, String credentialValidity, String locale) throws Exception {
        // Check if the credential can support SVG based rendering
        if (isSvgBasedRenderingSupported(vcCredentialResponse)) {
            log.info("Detected LDP VC v2 credential with svg template, using InjiVcRenderer for PDF generation");
            return generatePdfUsingSvgTemplate(vcCredentialResponse, issuerDTO, dataShareUrl);
        } else {
            log.info("Using v1 data model flow for credential");
            // Get the appropriate processor based on format
            CredentialFormatHandler processor = credentialFormatHandlerFactory.getHandler(vcCredentialResponse.getFormat());

            // Extract credential properties using the specific processor
            Map<String, Object> credentialProperties = processor.extractCredentialClaims(vcCredentialResponse);

            // Load display properties using the specific processor
            LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> displayProperties =
                    processor.loadDisplayPropertiesFromWellknown(credentialProperties, credentialsSupportedResponse, locale);

            Map<String, Object> data = getPdfResourceFromVcProperties(displayProperties, credentialsSupportedResponse,
                    vcCredentialResponse, issuerDTO, dataShareUrl, credentialValidity, locale);

            return renderVCInCredentialTemplate(data, issuerDTO.getIssuer_id(), credentialConfigurationId);
        }
    }

    private Map<String, Object> getPdfResourceFromVcProperties(
            LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> displayProperties,
            CredentialsSupportedResponse credentialsSupportedResponse,
            VCCredentialResponse vcCredentialResponse,
            IssuerDTO issuerDTO,
            String dataShareUrl,
            String credentialValidity,
            String userLocale) throws IOException, WriterException {

        Map<String, Object> data = new HashMap<>();
        LinkedHashMap<String, Object> rowProperties = new LinkedHashMap<>();

        CredentialSupportedDisplayResponse resolvedDisplay =
                Optional.ofNullable(credentialsSupportedResponse.getDisplay())
                        .filter(list -> !list.isEmpty())
                        .map(list -> list.stream()
                                .filter(d -> LocaleUtils.matchesLocale(d.getLocale(), userLocale))
                                .findFirst()
                                .orElseGet(list::getFirst))
                        .orElse(null);

        String backgroundColor = resolvedDisplay != null ? resolvedDisplay.getBackgroundColor() : null;
        String backgroundImage = resolvedDisplay != null && resolvedDisplay.getBackgroundImage() != null
                ? resolvedDisplay.getBackgroundImage().getUri()
                : null;
        String textColor = resolvedDisplay != null ? resolvedDisplay.getTextColor() : null;
        String credentialSupportedType = resolvedDisplay != null ? resolvedDisplay.getName() : null;

        SelectedFace selectedFace = extractFace(vcCredentialResponse);
        String face = selectedFace.face();
        String selectedFaceKey = selectedFace.key();

        Set<String> disclosures;
        if (CredentialFormat.VC_SD_JWT.getFormat().equals(vcCredentialResponse.getFormat())) {
            SDJWT sdjwt = SDJWT.parse((String) vcCredentialResponse.getCredential());
            disclosures = sdjwt.getDisclosures().stream()
                    .map(Disclosure::getClaimName)
                    .collect(Collectors.toSet());
        } else {
            disclosures = new LinkedHashSet<>();
        }

        LinkedHashMap<String, String> disclosuresProps = new LinkedHashMap<>();
        displayProperties.forEach((key, valueMap) -> {
            boolean isFaceKey = selectedFaceKey != null && key.trim().equals(selectedFaceKey);

            valueMap.forEach((display, val) -> {
                String displayName = display.getName();
                String locale = display.getLocale();
                String strVal = formatValue(val, locale);
                if (disclosures.contains(key)) {
                    disclosuresProps.put(key, displayName);
                    if (maskDisclosures) {
                        strVal = Utilities.maskValue(strVal);
                    }
                }
                if (!isFaceKey && displayName != null) {
                    rowProperties.put(key, Map.of(displayName, strVal));
                }
            });
        });

        String qrCodeImage = "";
        if (QRCodeType.OnlineSharing.equals(issuerDTO.getQr_code_type())) {
            qrCodeImage = constructQRCodeWithAuthorizeRequest(vcCredentialResponse, dataShareUrl);
        } else if (QRCodeType.EmbeddedVC.equals(issuerDTO.getQr_code_type())) {
            String claim169Qr = extractClaim169Qr(vcCredentialResponse);
            if(!claim169Qr.isEmpty()) {
                qrCodeImage = constructQRCode(claim169Qr);
            }
            else {
                qrCodeImage = constructQRCodeWithVCData(vcCredentialResponse);
            }
        }

        // is sd-jwt and has disclosures
        boolean isSdJwtWithDisclosures = CredentialFormat.VC_SD_JWT.getFormat().equals(vcCredentialResponse.getFormat()) && CollectionUtils.isNotEmpty(disclosures);

        data.put("isMaskedOn", maskDisclosures);
        data.put("isSdJwtWithDisclosures", isSdJwtWithDisclosures);
        data.put("qrCodeImage", qrCodeImage);
        data.put("credentialValidity", credentialValidity);
        data.put("logoUrl", issuerDTO.getDisplay().stream().map(d -> d.getLogo().getUrl()).findFirst().orElse(""));
        data.put("rowProperties", rowProperties);
        data.put("disclosures", disclosuresProps);
        data.put("textColor", textColor);
        data.put("backgroundColor", backgroundColor);
        data.put("backgroundImage", backgroundImage);
        data.put("titleName", credentialSupportedType);
        data.put("face", face);
        return data;
    }

    private String extractClaim169Qr(VCCredentialResponse vcCredentialResponse) {
        CredentialFormatHandler credentialFormatHandler = credentialFormatHandlerFactory.getHandler(vcCredentialResponse.getFormat());
        Map<String, Object> credentialSubject = credentialFormatHandler.extractCredentialClaims(vcCredentialResponse);
        Object claim169QrObj = credentialSubject.get(CLAIM_169_KEY);
        if (claim169QrObj instanceof Map<?, ?> claim169Map) {
            if (!claim169Map.isEmpty()) {
                Object firstValue = claim169Map.values().iterator().next();
                return firstValue != null ? firstValue.toString() : "";
            }
            return "";
        }
        return "";
    }

    private SelectedFace extractFace(VCCredentialResponse vcCredentialResponse) {
        // Use the appropriate credentialFormatHandler to extract credential properties
        CredentialFormatHandler credentialFormatHandler = credentialFormatHandlerFactory.getHandler(vcCredentialResponse.getFormat());
        Map<String, Object> credentialSubject = credentialFormatHandler.extractCredentialClaims(vcCredentialResponse);

        // handling face extraction based on configured keys
        List<String> faceKeys = Arrays.asList(faceImageLookupKeys.split(","));
        for (String faceKey : faceKeys) {
            String trimmedKey = faceKey.trim();
            Object faceValue = credentialSubject.get(trimmedKey);
            if (faceValue != null && !faceValue.toString().isEmpty()) {
                log.debug("Found face data using key: '{}'", trimmedKey);
                // Return the trimmedKey directly
                return new SelectedFace(trimmedKey, faceValue.toString());
            }
        }
        return new SelectedFace(null, null);
    }

    private String formatValue(Object val, String locale) {
        if (val instanceof Map) {
            return Optional.ofNullable(Stream.of(
                                    ((Map<?, ?>) val).get(LdpVcV2Constants.VALUE),
                                    ((Map<?, ?>) val).get(LdpVcV1Constants.VALUE),
                                    ((Map<?, ?>) val).get(SdJwtVcConstants.VALUE)
                            ).filter(Objects::nonNull)
                            .findFirst()
                            .orElse(null))
                    .map(Object::toString)
                    .orElse("");
        } else if (val instanceof List) {
            List<?> list = (List<?>) val;
            if (list.isEmpty()) return "";
            if (list.getFirst() instanceof String) {
                return String.join(", ", (List<String>) list);
            } else if (list.getFirst() instanceof Map<?, ?>) {
                return list.stream()
                        .filter(Objects::nonNull)
                        .map(item -> (Map<?, ?>) item)
                        .filter(m -> {
                            Object lang = Stream.of(
                                            m.get(LdpVcV2Constants.LANGUAGE),
                                            m.get(LdpVcV1Constants.LANGUAGE),
                                            m.get(SdJwtVcConstants.LANGUAGE)
                                    ).filter(Objects::nonNull)
                                    .findFirst()
                                    .orElse(null);

                            return lang != null && LocaleUtils.matchesLocale(lang.toString(), locale);
                        })
                        .map(m -> {
                            Object value = Stream.of(
                                            m.get(LdpVcV2Constants.VALUE),
                                            m.get(LdpVcV1Constants.VALUE),
                                            m.get(SdJwtVcConstants.VALUE)
                                    ).filter(Objects::nonNull)
                                    .findFirst()
                                    .orElse(null);

                            return value != null ? value.toString() : null;
                        })
                        .filter(Objects::nonNull)
                        .findFirst()
                        .orElse("");
            }
        }
        return val != null ? val.toString() : "";
    }

    private ByteArrayInputStream renderVCInCredentialTemplate(Map<String, Object> data, String issuerId, String credentialConfigurationId) {
        String credentialTemplate = utilities.getCredentialSupportedTemplateString(issuerId, credentialConfigurationId);
        Properties props = new Properties();
        props.setProperty("resource.loader", "class");
        props.setProperty("class.resource.loader.class", "org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader");
        Velocity.init(props);
        VelocityContext velocityContext = new VelocityContext(data);

        StringWriter writer = new StringWriter();
        Velocity.evaluate(velocityContext, writer, "Credential Template", credentialTemplate);

        String mergedHtml = writer.toString();
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        PdfWriter pdfwriter = new PdfWriter(outputStream);
        DefaultFontProvider defaultFont = new DefaultFontProvider(true, false, false);
        ConverterProperties converterProperties = new ConverterProperties();
        converterProperties.setFontProvider(defaultFont);
        HtmlConverter.convertToPdf(mergedHtml, pdfwriter, converterProperties);
        return new ByteArrayInputStream(outputStream.toByteArray());
    }

    private String constructQRCodeWithVCData(VCCredentialResponse vcCredentialResponse) throws JsonProcessingException, WriterException {
        String qrData = pixelPass.generateQRData(objectMapper.writeValueAsString(vcCredentialResponse.getCredential()), "");
        if (allowedQRDataSizeLimit > qrData.length()) {
            return constructQRCode(qrData);
        }
        return "";
    }

    private String constructQRCodeWithAuthorizeRequest(VCCredentialResponse vcCredentialResponse, String dataShareUrl) throws WriterException, JsonProcessingException {
        String qrData = buildOnlineSharingQrData(vcCredentialResponse, dataShareUrl);
        log.info("OnlineSharing QR payload length: {}", qrData.length());
        return constructQRCode(qrData);
    }

    private String buildOnlineSharingQrData(VCCredentialResponse vcCredentialResponse, String dataShareUrl) throws JsonProcessingException {
        PresentationDefinitionDTO presentationDefinitionDTO = presentationService.constructPresentationDefinition(vcCredentialResponse);
        String presentationString = objectMapper.writeValueAsString(presentationDefinitionDTO);
        Map<String, Object> dcqlQuery = presentationService.constructDcqlQuery(vcCredentialResponse);
        String dcqlString = objectMapper.writeValueAsString(dcqlQuery);
        return String.format(
                ovpQRDataPattern,
                URLEncoder.encode(dataShareUrl, StandardCharsets.UTF_8),
                URLEncoder.encode(presentationString, StandardCharsets.UTF_8),
                URLEncoder.encode(dcqlString, StandardCharsets.UTF_8));
    }

    private String constructQRCode(String qrData) throws WriterException {
        QRCodeWriter qrCodeWriter = new QRCodeWriter();
        BitMatrix bitMatrix = qrCodeWriter.encode(qrData, BarcodeFormat.QR_CODE, qrCodeWidth, qrCodeHeight);
        BufferedImage qrImage = MatrixToImageWriter.toBufferedImage(bitMatrix);
        return Utilities.encodeToString(qrImage, "png");
    }

    private boolean isSvgBasedRenderingSupported(VCCredentialResponse vcCredentialResponse) {
        if (!CredentialFormat.LDP_VC.getFormat().equals(vcCredentialResponse.getFormat())) {
            return false;
        }

        Object credentialPayload = vcCredentialResponse.getCredential();
        if (!(credentialPayload instanceof Map<?, ?>)) return false;

        @SuppressWarnings("unchecked")
        Map<String, Object> credentialPayloadMap = (Map<String, Object>) credentialPayload;

        return containsV2Context(credentialPayloadMap)
                && containsSvgTemplate(credentialPayloadMap);
    }

    private boolean containsV2Context(Map<String, Object> credentialPayloadMap) {
        Object contextField = credentialPayloadMap.get(LdpVcV2Constants.CONTEXT);

        if (contextField instanceof List<?> contextList)
            return contextList.stream().anyMatch(entry -> LdpVcV2Constants.V2_CONTEXT_URL.equals(entry.toString()));

        return false;
    }

    private boolean containsSvgTemplate(Map<String, Object> credentialPayloadMap) {
        Object renderMethod = credentialPayloadMap.get(LdpVcV2Constants.RENDER_METHOD);
        if (renderMethod instanceof List<?> renderMethodList) {
            return renderMethodList.stream().allMatch(entry -> {
                if (!(entry instanceof Map<?, ?> renderMethodProperties)) return false;

                String renderSuite = (String) renderMethodProperties.get(LdpVcV2Constants.RENDER_SUITE);
                return renderMethodProperties.containsKey(LdpVcV2Constants.TEMPLATE) && LdpVcV2Constants.SVG_MUSTACHE_RENDER_SUITE.equals(renderSuite);
            });
        }
        if (renderMethod instanceof Map<?, ?> renderMethodMap) {
            String renderSuite = (String) renderMethodMap.get(LdpVcV2Constants.RENDER_SUITE);
            return renderMethodMap.containsKey(LdpVcV2Constants.TEMPLATE) && LdpVcV2Constants.SVG_MUSTACHE_RENDER_SUITE.equals(renderSuite);
        }

        return false;
    }

    private ByteArrayInputStream generatePdfUsingSvgTemplate(VCCredentialResponse vcCredentialResponse, IssuerDTO issuerDTO, String dataShareUrl) throws Exception {
        try {
            // Get the ldp_vc credential and convert to string
            String credentialJsonString = objectMapper.writeValueAsString(vcCredentialResponse.getCredential());

            // Generate the QR code data to embed into the svg for Online Sharing
            String qrCodeData = null;
            if (QRCodeType.OnlineSharing.equals(issuerDTO.getQr_code_type())) {
                qrCodeData = buildOnlineSharingQrData(vcCredentialResponse, dataShareUrl);
                log.info("OnlineSharing SVG QR payload length: {}", qrCodeData.length());
            }

            // Generate list of rendered svg strings using InjiVcRenderer
            List<Object> generatedSvgObjects = injiVcRenderer.generateCredentialDisplayContent(
                    io.mosip.injivcrenderer.constants.CredentialFormat.LDP_VC, null, credentialJsonString, qrCodeData);

            if (generatedSvgObjects.isEmpty()) {
                 throw new Exception("No SVG content generated for v2 credential");
            }

            List<String> svgStrings = generatedSvgObjects.stream()
                    .map(Object::toString)
                    .map(svgFixerUtil::addMissingOffsetToStopElements)
                    .toList();

            log.debug("Fixed {} SVG elements for PDF conversion", svgStrings.size());

            String base64PdfContent = injiVcRenderer.convertSvgToPdf(svgStrings);
            byte[] decodedPdfBytes = Base64URL.from(base64PdfContent).decode();
            return new ByteArrayInputStream(decodedPdfBytes);
        } catch (Exception e) {
            log.error("Error generating PDF for v2 credential using InjiVcRenderer: {}", e.getMessage(), e);
            throw new Exception("Failed to generate PDF for v2 credential: " + e.getMessage(), e);
        }
    }
}
