package uk.demo.java.jwt_app;


import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/api/books")
public class BookApi {

    private List<String> bookList;

    public BookApi() {
        this.bookList = new ArrayList<>();
        bookList.add("Spring Boot 2");
        bookList.add("Pride and prejudice");
    }

    @GetMapping
    public List<String> getBookList() {
        return bookList;
    }

    @PostMapping
    public void setBook(@RequestBody String book){
        this.bookList.add(book);
    }
}
