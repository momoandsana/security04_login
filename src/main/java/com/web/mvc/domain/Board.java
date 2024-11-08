package com.web.mvc.domain;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;

@AllArgsConstructor
@NoArgsConstructor
@Setter
@Getter
@ToString
@Entity
@Builder
public class Board {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE,generator="board_id")
    @SequenceGenerator(allocationSize = 1,sequenceName = "board_id",name="board_id")
    private Long id;

    private String title;

    @Column(length = 100)
    private String content;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name="member_no")
    private Member member; // @ManyToOne 과 Member 객체를 선언해주면 알아서 연관관계를 맺어준다. 뒤에 오는 member 같은거는 중요하지 않다

    @CreationTimestamp
    private LocalDateTime regDate;

    @UpdateTimestamp
    private LocalDateTime updateDate;
}
