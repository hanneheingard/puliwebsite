package puli.xaidaz.jpa.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;
import puli.xaidaz.jpa.entity.Album;
import puli.xaidaz.jpa.entity.Dog;


@Repository
@Transactional
public interface AlbumRepository extends JpaRepository<Album, Long> {

    @Query("SELECT album FROM Album album WHERE album.title=(:title)")
    Album findByTitle(@Param("title") String title);

    @Modifying
    @Query("DELETE FROM Album album WHERE album.title=(:title)")
    void deleteByTitle(@Param("title") String title);
}
