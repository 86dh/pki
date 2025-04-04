package com.netscape.certsrv.authority;

import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Response;

import com.netscape.certsrv.acls.ACLMapping;
import com.netscape.certsrv.authentication.AuthMethodMapping;

@Path("authorities")
public interface AuthorityResource {

    public static final String HOST_AUTHORITY = "host-authority";

    @GET
    public Response findCAs(
            @QueryParam("id") String id,
            @QueryParam("parentID") String parentID,
            @QueryParam("dn") String dn,
            @QueryParam("issuerDN") String issuerDN
            /*
            @QueryParam("start") Integer start,
            @QueryParam("size") Integer size
            */
            ) throws Exception;

    @GET
    @Path("{id}")
    public Response getCA(@PathParam("id") String caIDString) throws Exception;

    @GET
    @Path("{id}/cert")
    @Produces("application/pkix-cert")
    public Response getCert(@PathParam("id") String caIDString);

    @GET
    @Path("{id}/cert")
    @Produces("application/x-pem-file")
    public Response getCertPEM(@PathParam("id") String caIDString);

    @GET
    @Path("{id}/chain")
    @Produces("application/pkcs7-mime")
    public Response getChain(@PathParam("id") String caIDString);

    @GET
    @Path("{id}/chain")
    @Produces("application/x-pem-file")
    public Response getChainPEM(@PathParam("id") String caIDString);

    @POST
    @AuthMethodMapping("authorities")
    @ACLMapping("authorities.create")
    public Response createCA(AuthorityData data);

    /**
     * Modify a CA (supports partial updates).
     *
     * isHostEnabled, authorityID, authorityParentID and DN are
     * immutable; differences in these values are ignored.
     *
     * Other values, if null, are ignored, otherwise they are
     * set to the new value.  To remove the description, use an
     * empty string.
     */
    @PUT
    @Path("{id}")
    @AuthMethodMapping("authorities")
    @ACLMapping("authorities.modify")
    public Response modifyCA(
        @PathParam("id") String caIDString,
        AuthorityData data);

    @POST
    @Path("{id}/enable")
    @AuthMethodMapping("authorities")
    @ACLMapping("authorities.modify")
    public Response enableCA(@PathParam("id") String caIDString);

    @POST
    @Path("{id}/disable")
    @AuthMethodMapping("authorities")
    @ACLMapping("authorities.modify")
    public Response disableCA(@PathParam("id") String caIDString);

    @POST
    @Path("{id}/renew")
    @AuthMethodMapping("authorities")
    @ACLMapping("authorities.modify")
    public Response renewCA(@PathParam("id") String caIDString);

    @DELETE
    @Path("{id}")
    @AuthMethodMapping("authorities")
    @ACLMapping("authorities.delete")
    public Response deleteCA(@PathParam("id") String caIDString);

}
