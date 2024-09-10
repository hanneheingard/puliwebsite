package puli.xaidaz.jpa.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.springframework.format.annotation.DateTimeFormat;

import java.time.LocalDate;
import java.time.LocalDateTime;

@Entity
@Table(name = "Dog")
public class Dog {

    @Id
    @GeneratedValue(strategy= GenerationType.IDENTITY)
    @Column(name = "ID")
    private Long id;
    @NotBlank(message = "Namn är obligatoriskt")
    @Column(name = "NAME")
    private String name;
    @NotBlank(message = "Uppfödarnamn är obligatoriskt")
    @Column(name = "BREEDING_NAME")
    private String breedingName;
    @NotBlank(message = "Färg är obligatoriskt")
    @Column(name = "COLOUR")
    private String colour;
    @DateTimeFormat(iso = DateTimeFormat.ISO.DATE)
    @NotNull(message = "Födelsedatum är obligatoriskt")
    @Column(name = "DATE_OF_BIRTH")
    private LocalDate dateOfBirth;
    @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME)
    @Column(name = "CREATED_AT")
    private LocalDateTime createdAt;
    @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME)
    @Column(name = "MODIFIED_AT")
    private LocalDateTime modifiedAt;
    @Column(name = "PROFILE_PICTURE")
    private String profilePicture;
    @Column(name = "DESCRIPTION")
    private String description;
    @Column(name = "LINK_TO_SKK")
    private String linkToSkk;
    @Column(name = "BREEDING_HISTORY")
    private String breedingHistory;

    // Getters and setters start

    public void setId(Long id) {
        this.id = id;
    }

    public Long getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public LocalDate getDateOfBirth() {
        return dateOfBirth;
    }

    public void setDateOfBirth(LocalDate dateOfBirth) {
        this.dateOfBirth = dateOfBirth;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime created_at) {
        this.createdAt = created_at;
    }

    public LocalDateTime getModifiedAt() {
        return modifiedAt;
    }

    public void setModifiedAt(LocalDateTime modifiedAt) {
        this.modifiedAt = modifiedAt;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getProfilePicture() {
        return profilePicture;
    }

    public void setProfilePicture(String profilePicture) {
        this.profilePicture = profilePicture;
    }

    public String getLinkToSkk() {
        return linkToSkk;
    }

    public void setLinkToSkk(String linkToSkk) {
        this.linkToSkk = linkToSkk;
    }

    public String getBreedingHistory() {
        return breedingHistory;
    }

    public void setBreedingHistory(String breedingHistory) {
        this.breedingHistory = breedingHistory;
    }

    public String getBreedingName() {
        return breedingName;
    }

    public void setBreedingName(String breedingName) {
        this.breedingName = breedingName;
    }

    public String getColour() {
        return colour;
    }

    public void setColour(String colour) {
        this.colour = colour;
    }

    // Getters and setters end

}
