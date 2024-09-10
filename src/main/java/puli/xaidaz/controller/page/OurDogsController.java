package puli.xaidaz.controller.page;

import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import puli.xaidaz.jpa.entity.Dog;
import puli.xaidaz.jpa.repository.DogRepository;
import puli.xaidaz.service.api.FileService;

import java.io.File;
import java.io.IOException;
import java.time.LocalDateTime;
import java.util.List;

@Controller
@RequestMapping(value = "/hundar")
public class OurDogsController {

    @Autowired DogRepository dogRepository;
    @Autowired FileService fileService;

    @GetMapping
    public String renderPageLayout(Model model) {
        List<Dog> allDogs = dogRepository.findAll();
        model.addAttribute("listOfDoges", allDogs);
        return "ourDogs";
    }

    @RequestMapping(path = "/hund")
    public String renderDog(@RequestParam("hundNamn") String dogName, Model model) {

        List<Dog> dogsWithName = dogRepository.findByName(dogName);

        model.addAttribute("dog", dogsWithName.get(0));
        return "dogProfile";
    }

    @Secured({"ROLE_ADMIN"})
    @RequestMapping(path = "/nyHund")
    public String addDog(Model model) {
        model.addAttribute("profilePictureLabel", "Ingen fil vald");
        return "newDog";
    }

    @Secured({"ROLE_ADMIN"})
    @RequestMapping(path = "/redigeraHund", method = RequestMethod.POST)
    public String editDog(@RequestParam("dogId") long dogId, Model model) {
        Dog dog = dogRepository.findById(dogId).get();

        model.addAttribute("dog", dog);
        model.addAttribute("profilePictureLabel", new File(dog.getProfilePicture()).getName());
        return "newDog";
    }

    @Secured({"ROLE_ADMIN"})
    @RequestMapping(value = "/sparaHund", method = RequestMethod.POST)
    public String saveDog(@RequestParam("profilePictureFile") MultipartFile profilePicture, @Valid @ModelAttribute("dog") Dog dog, BindingResult bindingResult) throws IOException {
        if (bindingResult.hasErrors()) {
            return "newDog";
        }

        if (dog.getId() == null) { // new dog
            dog.setCreatedAt(LocalDateTime.now());
            dog.setModifiedAt(LocalDateTime.now());
            setNewProfilePicture(profilePicture, dog);
        } else { // Existing dog
            Dog previousDog = dogRepository.findById(dog.getId()).get();

            String originalFileName = profilePicture.getOriginalFilename();
            if (originalFileName != null && !originalFileName.isEmpty() && (!previousDog.getProfilePicture().endsWith(originalFileName))) {
                fileService.deleteFile(previousDog.getProfilePicture());
                setNewProfilePicture(profilePicture, dog);
            }
        }

        dog.setModifiedAt(LocalDateTime.now());
        dogRepository.save(dog);
        return "redirect:/hundar";
    }

    @Secured({"ROLE_ADMIN"})
    @ResponseBody
    @RequestMapping(value = "/taBort", method = RequestMethod.POST)
    public String deleteDog(@RequestParam("id") long id) {
        dogRepository.findById(id).ifPresent( d -> {
            fileService.deleteFile(d.getProfilePicture());
            dogRepository.delete(d);
        });
        return "OK";
    }

    private void setNewProfilePicture(MultipartFile profilePicture, Dog dog) throws IOException {
        if (dog.getId() == null) {
            dogRepository.save(dog);
        }

        if (!profilePicture.getOriginalFilename().isEmpty()) {
            String fileName = fileService.saveFile(profilePicture, dog.getName() + dog.getId().toString());
            dog.setProfilePicture(fileName);
        } else {
            dog.setProfilePicture("/images/dogs/bild_saknas.png");
        }
    }
}
