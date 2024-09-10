package puli.xaidaz.controller.page;

import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import puli.xaidaz.jpa.entity.News;
import puli.xaidaz.jpa.repository.NewsRepository;
import puli.xaidaz.service.api.FileService;

import java.io.File;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

@Controller
@RequestMapping(value = "/nyheter")
public class NewsController {

    @Autowired
    NewsRepository newsRepository;
    @Autowired
    FileService fileService;

    @GetMapping
    public String renderPageLayout(Model model) {
        List<News> allNews = newsRepository.findAll();
        allNews.sort(Comparator.comparing(News::getCreatedAt).reversed());

        Map<String, List<News>> newsByMonthMap = new LinkedHashMap<>();
        for (News news : allNews) {
            String year = String.valueOf(news.getCreatedAt().getYear());
            String month = news.getCreatedAt().format(DateTimeFormatter.ofPattern("MMMM", new Locale("sv","SE")));
            newsByMonthMap.computeIfAbsent(StringUtils.capitalize(month)+ " " +year, k -> new ArrayList<>()).add(news);
        }

        model.addAttribute("newsByMonthMap", newsByMonthMap);

        return "news";
    }

    @Secured({"ROLE_ADMIN"})
    @RequestMapping(path = "/nyNyhet")
    public String addNews() {
        return "addNews";
    }

    @Secured({"ROLE_ADMIN"})
    @RequestMapping(path = "/redigeraNyhet", method = RequestMethod.POST)
    public String editNews(@RequestParam("id") long id, Model model) {
        News news = newsRepository.findById(id).get();

        model.addAttribute("news", news);
        if (news.getProfilePicture() != null) {
            model.addAttribute("profilePictureLabel", new File(news.getProfilePicture()).getName());
        }
        return "addNews";
    }

    @Secured({"ROLE_ADMIN"})
    @ResponseBody
    @RequestMapping(value = "/taBort", method = RequestMethod.POST)
    public String deleteNews(@RequestParam("id") long id) {
        newsRepository.findById(id).ifPresent(d -> {
            if (d.getProfilePicture() != null) {
                fileService.deleteFile(d.getProfilePicture());
            }
            newsRepository.delete(d);
        });
        return "OK";
    }

    @Secured({"ROLE_ADMIN"})
    @RequestMapping(value = "/sparaNyhet", method = RequestMethod.POST)
    public String saveNews(@RequestParam("profilePictureFile") MultipartFile profilePicture, @Valid @ModelAttribute("news") News news, BindingResult bindingResult) throws IOException {
        if (bindingResult.hasErrors()) {
            return "addNews";
        }

        if (news.getId() == null) { // new News
            news.setCreatedAt(LocalDateTime.now());
            news.setModifiedAt(LocalDateTime.now());
            setNewProfilePicture(profilePicture, news);
        } else { // Existing News
            News exisitingNews = newsRepository.findById(news.getId()).get();

            String fileName = profilePicture.getOriginalFilename();
            if (fileName != null && !fileName.isEmpty() && (!exisitingNews.getProfilePicture().endsWith(fileName))) {
                fileService.deleteFile(exisitingNews.getProfilePicture());
                setNewProfilePicture(profilePicture, news);
            }
        }

        news.setModifiedAt(LocalDateTime.now());
        news.setProfilePicture(news.getProfilePicture().equals("") ? null : news.getProfilePicture());
        newsRepository.save(news);
        return "redirect:/nyheter";
    }

    private void setNewProfilePicture(MultipartFile profilePicture, News news) throws IOException {
        if (news.getId() == null) {
            newsRepository.save(news);
        }

        if (!profilePicture.getOriginalFilename().isEmpty()) {
            String fileName = fileService.saveFile(profilePicture, news.getTitle() + news.getId().toString());
            news.setProfilePicture(fileName);
        }
    }
}
