<%@page pageEncoding="UTF-8" %>
<%@ include file="fragments/header.jsp" %>
<%@ include file="fragments/navigation.jsp" %>
<%@ page import="java.time.format.DateTimeFormatter" %>

<body>


<!-- Slider Start -->
<section class="slider"
         style="background-image: linear-gradient(to bottom, rgba(255,255,255,0.1) 0%,rgba(255,255,255,0.1) 100%), url(images/dogs/jump_puli.jpg)">
    <div class="container">
        <div class="row">
            <div class="col-md-12">
                <div class="block">
                    <h1 class="animated fadeInUp">Välkommen!<br></h1>
                    <p class="animated fadeInUp">Vår kennel har uppfödning av den ungerska rasen <strong>Puli</strong> i
                        närheten av
                        Trelleborg, Skåne </br> </p>
                </div>
            </div>
        </div>
    </div>
</section>

<!-- Wrapper Start -->
<section class="about section">
    <div class="container">
        <div class="row" style="margin-top: 2rem">
            <div class="col-md-7">
                <div class="block">
                    <div class="section-title">
                        <h2>Om oss</h2>
                    </div>
                </div>
            </div>
        </div>
        <div class="row">
            <div class="col-md-7">
                <div class="block">
                    <jsp:include page="fragments/editableTextField.jsp" >
                        <jsp:param name="textKey" value="aboutUs" />
                    </jsp:include>
                    <p class="broedtekst-frontpage">Puli är en fantastisk hund som blir din bästa vän!</p>
                    <img src="${pageContext.request.contextPath}/images/dogs/dogs_stairs.png" style="width: 50%" alt="Img">
                </div>
            </div><!-- .col-md-7 close -->
            <div class="col-md-5">
                <div class="block">
                    <div class="card customCard mb-3 mt-4 w-100">
                        <h3 class="mt-2 ml-3 mb-4"><a class="text-dark" href="${pageContext.request.contextPath}/nyheter">Senaste nyheter</a></h3>
                        <c:forEach var="newsDTO" items="${newsDTOList}">
                            <a class="text-dark" href="${pageContext.request.contextPath}/nyheter#${newsDTO.id}">
                                <div class="row align-items-center px-4">
                                    <div class="col-md-5">
                                        <c:set var="hasProfilePic" value="${newsDTO.profilePicture != null && !newsDTO.profilePicture.isEmpty()}"/>
                                        <c:if test="${hasProfilePic}">
                                            <img src="<c:url value="${newsDTO.profilePicture}"/>" class="img-fluid rounded-start ml-2 mb-3 center-cropped" alt="...">
                                        </c:if>
                                    </div>
                                    <div class="col-md-7">
                                        <div class="card-title">${newsDTO.title}</div>
                                        <div class="text-muted">${newsDTO.createdAt.format( DateTimeFormatter.ofPattern("yyyy-MM-dd"))}</div>
                                    </div>
                                </div>
                            </a>
                        </c:forEach>
                    </div>
                </div>
            </div><!-- .col-md-5 close -->
            <div class="col-md-12 items-align text-center">
                <hr style="background: #1d192c;  width: auto" class="my-4">
                <p class="broedtekst-frontpage">Välkommen att höra av dig till oss.</p>
                <a href="${pageContext.request.contextPath}/kontakt" class="btn-main animated fadeInUp">Kontakta oss</a>
            </div>
        </div>
    </div>
</section>

</body>
<%@ include file="fragments/footer.jsp" %>
</html>
