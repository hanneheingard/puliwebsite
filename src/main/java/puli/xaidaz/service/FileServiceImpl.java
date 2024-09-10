package puli.xaidaz.service;

import jakarta.annotation.PostConstruct;
import org.apache.commons.io.FileUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import puli.xaidaz.service.api.FileService;

import java.io.File;
import java.io.IOException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@Service
public class FileServiceImpl implements FileService {

    @Value("${uploadResourceRootPath}")
    private String uploadResourceRootPath;

    private static final String UPLOAD_URL = "/uploads/";

    private Path ROOT_PATH;

    @PostConstruct
    public void init() throws IOException {
//        clearFolders(); //Only include this line to delete entire upload folder!!!!
        ROOT_PATH = Paths.get(uploadResourceRootPath);
        createDirectoryIfNotExists(ROOT_PATH);
        Path ALBUMS_PATH = Paths.get(uploadResourceRootPath+ "albums");
        createDirectoryIfNotExists(ALBUMS_PATH);
    }

    @Override
    public String saveFile(MultipartFile file, String subPath) throws IOException {
        String fullPath = ROOT_PATH +File.separator+ subPath;
        createDirectoryIfNotExists(fullPath);

        String fileName = fullPath + File.separator + file.getOriginalFilename();
        file.transferTo(Paths.get(fileName));

        return UPLOAD_URL + subPath + File.separator + file.getOriginalFilename();
    }

    @Override
    public boolean deleteFile(String path) {
        return new File(path).delete();
    }

    @Override
    public byte[] getFile(String filename) {
        return new byte[0];
    }

    private void createDirectoryIfNotExists(String path) throws IOException {
        createDirectoryIfNotExists(Paths.get(path));
    }

    private void createDirectoryIfNotExists(Path path) throws IOException {
        String absolutePath = path.toAbsolutePath().toString();
        System.out.println("FILESERVICE Creating " +absolutePath);
        try {
            Files.createDirectory(path);
        } catch (FileAlreadyExistsException e) {
            System.out.println("Uploads folder " +absolutePath+ " already exists. Do nothing.");
        }
        System.out.println("FILESERVICE done creating " +absolutePath);

    }

    private void clearFolders() throws IOException {
        try {
            FileUtils.cleanDirectory(ROOT_PATH.toFile());
        }  catch (IllegalArgumentException e) {
            System.out.println("Uploads folder didnt exists. Do nothing.");
        }
        System.out.println("All files in root path " +ROOT_PATH.toFile()+ " cleared.");
    }
}
