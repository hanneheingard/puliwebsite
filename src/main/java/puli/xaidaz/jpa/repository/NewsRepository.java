package puli.xaidaz.jpa.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;
import puli.xaidaz.jpa.entity.News;

import java.util.List;

@Repository
@Transactional
public interface NewsRepository extends JpaRepository<News, Long> {

    @Query("SELECT news FROM News news WHERE news.title=(:title)")
    List<News> findByTitle(@Param("title") String title);

    @Query(value = "SELECT * FROM News ORDER BY CREATED_AT DESC LIMIT :limit", nativeQuery = true)
    List<News> findLatestByCreatedAt(@Param("limit") int limit);
}
