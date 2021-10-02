package wrappedkey.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import wrappedkey.payload.DeviceInfoDTO;
import wrappedkey.payload.WrappedKeyDTO;
import wrappedkey.service.WrappedKeyService;

import java.security.cert.CertificateException;

@RestController
public class MainController {

    private WrappedKeyService wrappedKeyService = new WrappedKeyService();

    @PostMapping("/getWrappedKey")
    public ResponseEntity<WrappedKeyDTO> getWrappedKey(@RequestBody DeviceInfoDTO deviceInfoDTO) throws CertificateException {
        WrappedKeyDTO wrappedKeyDTO = new WrappedKeyDTO();
        wrappedKeyDTO.wrappedKey = wrappedKeyService.generateB64WrappedKey(deviceInfoDTO.deviceCertificate);
        return new ResponseEntity(wrappedKeyDTO, HttpStatus.OK);
    }
}
