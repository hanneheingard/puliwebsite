package puli.xaidaz.jpa.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;
import puli.xaidaz.jpa.entity.Picture;

import java.util.List;

@Repository
@Transactional
public interface PictureRepository extends JpaRepository<Picture, Long> {


    @Query("SELECT picture FROM Picture picture JOIN FETCH picture.album album WHERE picture.title = (:title) and album.title = (:albumTitle)")
    Picture findByTitleAndAlbumTitle(@Param("title") String title, @Param("albumTitle") String albumTitle);

    @Query("SELECT picture FROM Picture picture JOIN FETCH picture.album album WHERE album.title = (:albumTitle)")
    List<Picture> findByAlbumTitle(@Param("albumTitle") String albumTitle);

    @Query("SELECT CASE WHEN count(picture) > 0 THEN true ELSE false end FROM Picture picture JOIN picture.album album WHERE album.title = (:albumTitle)")
    boolean existsByAlbumTitle(@Param("albumTitle") String albumTitle);

    @Modifying
    @Query("DELETE FROM Picture picture WHERE picture.album.id = (:id)")
    void deleteByAlbumId(@Param("id") Long id);
}
