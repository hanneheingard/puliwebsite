package puli.xaidaz.jpa.entity;

import jakarta.persistence.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "Text")
public class Text {

    @Id
    @GeneratedValue(strategy= GenerationType.AUTO)
    @Column(name = "ID")
    private Long id;
    @Column(name = "TEXT_KEY")
    private String textKey;
    @Column(name = "TEXT_GROUP")
    private String textGroup;
    @Column(name = "TEXT")
    private String text;

    public Text() {
    }

    // Getters and setters start

    public void setId(Long id) {
        this.id = id;
    }

    public Long getId() {
        return id;
    }

    public String getTextKey() {
        return textKey;
    }

    public void setTextKey(String textKey) {
        this.textKey = textKey;
    }

    public String getTextGroup() {
        return textGroup;
    }

    public void setTextGroup(String textGroup) {
        this.textGroup = textGroup;
    }

    public String getText() {
        return text;
    }

    public void setText(String text) {
        this.text = text;
    }

    // Getters and setters end

}
