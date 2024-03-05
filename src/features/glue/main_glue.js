/**
 * File Name : main_glue.js
 * Date Created : 2023.04.25
 * Writer  :배태주
 * Description : main_glue.html에서 발생하는 이벤트 처리를 위한 JavaScript
 **/

// document.ready 영역 시작
pluginpath = '/usr/share/cockpit/ablestack';
var console_log = true;

$(document).ready(function(){
    $('#div-modal-wizard-gateway-vm').load("./src/features/glue/gateway-vm-wizard.html");
    $('#div-modal-wizard-gateway-vm').hide();

    $('#dropdown-menu-storage-system-status').hide();
    $('#dropdown-menu-iscsi-status').hide();
    // gluefs 구성 화면 로드
    $('#div-modal-gluefs-construction').load("./src/features/glue/gluefs-construction.html");
    $('#div-modal-gluefs-construction').hide();
    // nfs 구성 화면 로드
    $('#div-modal-nfs-construction').load("./src/features/glue/nfs-construction.html");
    $('#div-modal-nfs-construction').hide();
    // smb 구성 화면 로드
    $('#div-modal-smb-construction').load("./src/features/glue/smb-construction.html");
    $('#div-modal-smb-construction').hide();

    $('#menu-item-set-gluefs-delete').hide();
    $('#menu-item-set-nfs-delete').hide();
    $('#menu-item-set-smb-delete').hide();
    $('#menu-item-set-iscsi-delete').hide();
    $('#menu-item-set-iscsi-service-control').hide();
    $('#menu-item-set-iscsi-target-create').hide();
    $('#menu-item-set-iscsi-acl-connect').hide();

    gwvmInfoSet();
    gluefsList();
    nfsClusterList();
    nfsExportList();
    iscsiServiceList();
    iscsiTargetList();
    smbServiceList();
    glueVmList();

    setInterval(() => {
        gwvmInfoSet(),glueVmList()
        // ,gluefsList(),nfsClusterList(),nfsExportList(),iscsiServiceList(),smbServiceList()
    }, 10000);
});
// document.ready 영역 끝

// 이벤트 처리 함수
// 상태 보기 드롭다운 메뉴를 활성화한 상태에서 다른 영역을 클릭 했을 경우 메뉴 닫기 (현재 활성화된 iframe 클릭할 때 작동)
$('html').on('click', function(e){
    console.log(e);
    if(!$(e.target).hasClass('pf-c-dropdown__toggle')){
        $('.pf-c-dropdown__menu, .pf-m-align-right').hide();
    }
    // if($(e.target).hasClass('pf-c-select__menu-item')){
        
    //     if($('#div-glue-hosts-list').css("display") != "none"){
    //         alert(111111111)
    //     }else{
    //         alert(222222)
    //     }
    //     // $('.pf-c-select__menu').hide();
    // }
});

// 상태 보기 드롭다운 메뉴를 활성화한 상태에서 다른 영역을 클릭 했을 경우 메뉴 닫기 (pareant html 클릭할 때 작동)
$(top.document, 'html').on('click', function(e){
    if(!$(e.target).hasClass('pf-c-dropdown__toggle')){
        $('.pf-c-dropdown__menu, .pf-m-align-right').hide();
    }
});

$('#card-action-gateway-vm-status').on('click', function(){
    $('#dropdown-menu-gateway-vm-status').toggle();
});

$('#button-open-modal-wizard-gateway-vm').on('click', function(){
    $('#div-modal-wizard-gateway-vm').show();
});

// 파일 시스템 눈금 클릭 시
$('#card-action-storage-cluster-system-status').on('click',function(){

    if( $('#gluefs-status').text() != 'Health Err' || $('#nfs-status').text() != 'Health Err' || $('#smb-status').text() != 'Health Err'){
        $('#menu-item-set-filesystem-control').removeClass('pf-m-disabled');
        $('#menu-item-set-filesystem-control').addClass('pf-m-enabled');
    }else{
        $('#menu-item-set-filesystem-control').removeClass('pf-m-enabled');
        $('#menu-item-set-filesystem-control').addClass('pf-m-disabeld');
    }
    $('#dropdown-menu-storage-system-status').toggle();
});

// iscsi 눈금 클릭 시
$('#card-action-storage-cluster-iscsi-status').on('click', function(){
        if($('#iscsi-status').text() == "Health Err"){
            $('#menu-item-set-iscsi-delete').hide();
            $('#menu-item-set-iscsi-service-control').hide();
            $('#menu-item-set-iscsi-target-create').hide();
            $('#menu-item-set-iscsi-acl-connect').hide();
            $('#menu-item-set-iscsi-construction').show();
        }else{
            $('#menu-item-set-iscsi-delete').show();
            $('#menu-item-set-iscsi-service-control').show();
            $('#menu-item-set-iscsi-target-create').show();
            $('#menu-item-set-iscsi-acl-connect').show();
            $('#menu-item-set-iscsi-construction').hide();
        }
    $('#dropdown-menu-iscsi-status').toggle();
});

/** 스토리지 서비스 구성 관련 action start */
$('#button-glue-api-server-connect').on('click', function(){
    window.open("https://10.10.5.11:8080/swagger/index.html");
});

/** 스토리지 서비스 구성 관련 action start */
$('#button-gateway-vm-setup2').on('click', function(){
    $('#div-modal-gateway-vm-setup').show();
});

$('#menu-item-gateway-vm-setup').on('click', function(){
    $('#div-modal-gateway-vm-setup').show();
});

// iscsi 구성 화면 닫기
$('#div-modal-iscsi-close, #button-cancel-iscsi').on('click', function(){
    $('#div-modal-iscsi').hide();
});
// iscsi 구성
$('#button-execution-iscsi').on('click', function(){
    $('#div-modal-iscsi').hide();
    $('#div-modal-spinner-header-txt').text('iSCSI 구성 중');
    $('#div-modal-spinner').show();
    setTimeout(function(){
        cockpit.spawn(['python3', pluginpath + '/python/glue/iscsi.py', 'config']).then(function(data){
        var retVal = JSON.parse(data);
        if(retVal.code == 200){
            $('#modal-status-alert-title').text("iSCSI 구성");
            $('#modal-status-alert-body').text("iSCSI 구성 완료되었습니다.");
            $('#div-modal-status-alert').show();
        }else{
            $('#modal-status-alert-title').text("iSCSI 구성");
            $('#modal-status-alert-body').text("iSCSI 구성 실패했습니다.");
            $('#div-modal-status-alert').show();
        }
    })}, 5000)

});
//gluefs 구성 화면 열기
$('#menu-item-set-gluefs-construction').on('click',function(){
    localStorage.clear();
    sessionStorage.clear();
    $('#div-modal-gluefs-construction').show();
});
// nfs 구성 화면 열기
$('#menu-item-set-nfs-construction').on('click',function(){
    localStorage.clear();
    sessionStorage.clear();
    $('#div-modal-nfs-construction').show();
});
// smb 구성 화면 열기
$('#menu-item-set-smb-construction').on('click',function(){
    localStorage.clear();
    sessionStorage.clear();
    $('#div-modal-smb-construction').show();
});
// iscsi 구성 화면 열기
$('#menu-item-set-iscsi-construction').on('click', function(){
    $('#modal-title-iscsi').text("iSCSI 구성");
    $('#modal-body-iscsi').text("iSCSI 구성 하시겠습니까?")
    $('#div-modal-iscsi').show();
});

// div-modal-alert-button-confirm 클릭시
$('#modal-status-alert-button-confirm').on('click',function(){
    $('#div-modal-status-alert').hide();
    // location.reload();
});
// alert modal 닫기
$('#modal-status-alert-button-close1, #modal-status-alert-button-close2').on('click', function(){
    $('#div-modal-status-alert').hide();
});

// 삭제 modal 닫기
$('#button-cancel-modal-delete, #button-close-modal-delete').on('click',function(){
    $('#div-modal-all-delete').hide();
});
// gluefs 편집 열기
$('#gluefs-edit').on('click',function(){
    sessionStorage.setItem('type','gluefs_edit');

        $('#gluefs-construction-type').attr('style', "display:none;");
        $('#modal-title-gluefs-construciton').text('GlueFS 편집');
        $('#div-modal-gluefs-construction').show();

});
// nfs 편집 열기
$('#nfs-edit').on('click',function(){
    sessionStorage.setItem('type','nfs_edit');

    $('#modal-title-nfs-construciton').text('NFS 편집');
    $('#div-modal-nfs-construction').show();
});
// smb 편집 열기
$('#smb-edit').on('click',function(){
    sessionStorage.setItem('type','smb_edit');

    $('#smb-group-user, #smb-group-password').attr('style','display:none;');
    $('#modal-title-smb-construciton').text('SMB 편집');
    $('#div-modal-smb-construction').show();
});
// 파일 시스템 서비스 제어 열림
$('#menu-item-set-filesystem-control').on('click',function(){
    sessionStorage.clear();
    $('#div-modal-file-system-control').show();
});
// 파일 시스템 서비스 제어 닫힘
$('#button-close-file-system-control, #button-cancel-modal-file-system-control').on('click',function(){
    sessionStorage.clear();
    $('#div-modal-file-system-control').hide();
});
// 파일 시스템 서비스 실행 버튼 클릭 시
$('#button-execution-modal-file-system-control').on('click',function(){
    var service_name = $('#form-select-file-system-service-control').val();
    var service_action = $('#form-select-service-control-action').val();

    if(service_name == 'gluefs'){
            $('#div-modal-file-system-control').hide();
            $('#div-modal-spinner-header-txt').text('GlueFS 서비스 제어 중');
            $('#div-modal-spinner').show();

            var cmd = ['python3', pluginpath + '/python/glue/gluefs.py', 'daemon', '--control', service_action];
            cockpit.spawn(cmd).then(function(data){
                var retVal = JSON.parse(data);
                var retVal_code = JSON.parse(retVal.code);

                $('#div-modal-spinner').hide();

                if(service_action == 'stop'){
                    if(retVal_code == 200){
                        $('#modal-status-alert-title').text("GlueFS 서비스 제어");
                        $('#modal-status-alert-body').text("GlueFS 서비스가 정지되었습니다.");
                        $('#div-modal-status-alert').show();
                    }
                    else{
                        $('#modal-status-alert-title').text("GlueFS 서비스 제어");
                        $('#modal-status-alert-body').text("GlueFS 서비스를 정지 시키는 데 실패했습니다.");
                        $('#div-modal-status-alert').show();
                    }
                }
                else{
                    if(retVal_code == 200){
                        $('#modal-status-alert-title').text("GlueFS 서비스 제어");
                        $('#modal-status-alert-body').text("GlueFS 서비스가 시작되었습니다.");
                        $('#div-modal-status-alert').show();
                    }
                    else{
                        $('#modal-status-alert-title').text("GlueFS 서비스 제어");
                        $('#modal-status-alert-body').text("GlueFS 서비스를 시작 시키는 데 실패했습니다.");
                        $('#div-modal-status-alert').show();
                    }
                }

            });
    }
    else if(service_name == 'nfs'){
        $('#div-modal-file-system-control').hide();
        $('#div-modal-spinner-header-txt').text('NFS 서비스 제어 중');
        $('#div-modal-spinner').show();

        var cmd = ['python3', pluginpath + '/python/glue/nfs.py', 'daemon', '--control', service_action];
        cockpit.spawn(cmd).then(function(data){
            var retVal = JSON.parse(data);
            var retVal_code = JSON.parse(retVal.code);
            $('#div-modal-spinner').hide();
            if(service_action == 'stop'){
                if(retVal_code == 200){
                    $('#modal-status-alert-title').text("NFS 서비스 제어");
                    $('#modal-status-alert-body').text("NFS 서비스가 정지되었습니다.");
                    $('#div-modal-status-alert').show();
                }
                else{
                    $('#modal-status-alert-title').text("NFS 서비스 제어");
                    $('#modal-status-alert-body').text("NFS 서비스를 정지 시키는 데 실패했습니다.");
                    $('#div-modal-status-alert').show();
                }
            }
            else{
                if(retVal_code == 200){
                    $('#modal-status-alert-title').text("NFS 서비스 제어");
                    $('#modal-status-alert-body').text("NFS 서비스가 시작되었습니다.");
                    $('#div-modal-status-alert').show();
                }
                else{
                    $('#modal-status-alert-title').text("NFS 서비스 제어");
                    $('#modal-status-alert-body').text("NFS 서비스를 시작 시키는 데 실패했습니다.");
                    $('#div-modal-status-alert').show();
                }
            }
        });
        }
    else if(service_name == 'smb'){
        $('#div-modal-file-system-control').hide();
        $('#div-modal-spinner-header-txt').text('SMB 서비스 제어 중');
        $('#div-modal-spinner').show();

        var cmd = ['python3', pluginpath + '/python/glue/smb.py', service_action,'-sn','smb'];
        cockpit.spawn(cmd).then(function(data){
            var retVal = JSON.parse(data);
            $('#div-modal-spinner').hide();
            if(service_action == 'stop'){
                if(retVal.code == 200){
                    $('#modal-status-alert-title').text("SMB 서비스 제어");
                    $('#modal-status-alert-body').text("SMB 서비스가 정지되었습니다.");
                    $('#div-modal-status-alert').show();

                    localStorage.setItem('smb','stop');
                }
                else{
                    $('#modal-status-alert-title').text("SMB 서비스 제어");
                    $('#modal-status-alert-body').text("SMB 서비스를 정지 시키는 데 실패했습니다.");
                    $('#div-modal-status-alert').show();
                }
            }
            else{
                if(retVal.code == 200){
                    $('#modal-status-alert-title').text("SMB 서비스 제어");
                    $('#modal-status-alert-body').text("SMB 서비스가 시작되었습니다.");
                    $('#div-modal-status-alert').show();
                }
                else{
                    $('#modal-status-alert-title').text("SMB 서비스 제어");
                    $('#modal-status-alert-body').text("SMB 서비스를 시작 시키는 데 실패했습니다.");
                    $('#div-modal-status-alert').show();
                }
            }
        });
    }
});
// iscsi 서비스 제어 버튼 클릭 시
$('#menu-item-set-iscsi-service-control').on('click', function(){
    $('#div-modal-iscsi-control').show();
});
// iscsi 서비스 제어 취소 버튼 시
$('#button-close-iscsi-control, #button-cancel-modal-iscsi-control').on('click', function(){
    $('#div-modal-iscsi-control').hide();
});
// iscsi 서비스 제어 실행 클릭 시
$('#button-execution-modal-iscsi-control').on('click', function(){

    var action = $('#form-select-iscsi-service-control-action').val();

    $('#div-modal-iscsi-control').hide();
    $('#div-modal-spinner-header-txt').text('iSCSI 서비스 제어 중');
    $('#div-modal-spinner').show();

    cockpit.spawn(['python3', pluginpath + '/python/glue/iscsi.py', 'daemon', '--control', action]).then(function(data){
        var retVal = JSON.parse(data);
        if(action == 'stop'){
            if(retVal.code == 200){
                $('#modal-status-alert-title').text("iSCSI 서비스 제어");
                $('#modal-status-alert-body').text("iSCSI 서비스가 정지되었습니다.");
                $('#div-modal-status-alert').show();

                localStorage.setItem('iscsi','stop');
            }
            else{
                $('#modal-status-alert-title').text("iSCSI 서비스 제어");
                $('#modal-status-alert-body').text("iSCSI 서비스를 정지 시키는 데 실패했습니다.");
                $('#div-modal-status-alert').show();
            }
        }
        else{
            if(retVal.code == 200){
                $('#modal-status-alert-title').text("iSCSI 서비스 제어");
                $('#modal-status-alert-body').text("iSCSI 서비스가 시작되었습니다.");
                $('#div-modal-status-alert').show();
            }
            else{
                $('#modal-status-alert-title').text("iSCSI 서비스 제어");
                $('#modal-status-alert-body').text("iSCSI 서비스를 시작 시키는 데 실패했습니다.");
                $('#div-modal-status-alert').show();
            }
        }

    });
});
// gluefs 삭제 버튼 클릭 시
$('#menu-item-set-gluefs-delete').on('click',function(){

    sessionStorage.setItem('type','gluefs_delete');

    $('#div-modal-delete-title').text("GlueFS 삭제");
    $('#div-modal-delete-body').text("GlueFS를 삭제하시겠습니까?");
    $('#div-modal-delete-body-p').text("(GlueFS 삭제 시 SMB,NFS 삭제를 먼저 이행 하셔야 합니다.)");
    $('#div-modal-delete-body-p').show();
    if ($('#nfs-status').text() == "Health Err" && $('#smb-status').text() == "Health Err"){
        $('#button-execution-modal-delete').addClass('pf-m-enabled');
        $('#button-execution-modal-delete').removeClass('pf-m-disabled');
    }else{
        $('#button-execution-modal-delete').addClass('pf-m-disabled');
        $('#button-execution-modal-delete').removeClass('pf-m-enabled');
    }

    $('#div-modal-all-delete').show();
});
// nfs 삭제 버튼 클릭 시
$('#menu-item-set-nfs-delete').on('click',function(){

    sessionStorage.setItem('type','nfs_delete');

    $('#div-modal-delete-title').text("NFS 삭제");
    $('#div-modal-delete-body').text("NFS를 삭제하시겠습니까?");
    $('#div-modal-delete-body-p').hide();
    $('#button-execution-modal-delete').removeClass('pf-m-disabled');
    $('#button-execution-modal-delete').removeClass('pf-m-enabled');
    $('#div-modal-all-delete').show();
});
// smb 삭제 버튼 클릭 시
$('#menu-item-set-smb-delete').on('click',function(){

    sessionStorage.setItem('type','smb_delete');

    $('#div-modal-delete-title').text("SMB 삭제");
    $('#div-modal-delete-body').text("SMB를 삭제하시겠습니까?");
    $('#div-modal-delete-body-p').hide();
    $('#button-execution-modal-delete').removeClass('pf-m-disabled');
    $('#button-execution-modal-delete').removeClass('pf-m-enabled');
    $('#div-modal-all-delete').show();
});
// iscsi 삭제 버튼 클릭 시
$('#menu-item-set-iscsi-delete').on('click', function(){
    sessionStorage.setItem('type', 'iscsi_delete');

    $('#div-modal-delete-title').text("iSCSI 삭제");
    $('#div-modal-delete-body').text("iSCSI를 삭제하시겠습니까?");
    $('#div-modal-delete-body-p').text("iSCSI 삭제 진행 시, 타겟 및 이미지도 완전 삭제됩니니다.");
    $('#div-modal-delete-body-p').show();
    $('#button-execution-modal-delete').removeClass('pf-m-disabled');
    $('#button-execution-modal-delete').removeClass('pf-m-enabled');
    $('#div-modal-all-delete').show();

});
// 삭제 실행 버튼 클릭 시
$('#button-execution-modal-delete').on('click',function(){

    var delete_session = sessionStorage.getItem('type');

    localStorage.clear();

    $('#div-modal-all-delete').hide();

    if(delete_session == 'gluefs_delete'){
        $('#div-modal-spinner-header-txt').text('GlueFS 삭제 중');
        $('#div-modal-spinner').show();

        cockpit.spawn(['python3', pluginpath + '/python/glue/gluefs.py','delete']).then(function(data){
            var retVal = JSON.parse(data);
            var retVal_code = JSON.parse(retVal.code);
            if(retVal_code == 200){
                cockpit.spawn(['python3', pluginpath + '/python/glue/gluefs.py', 'destroy']).then(function(data){
                    var retVal = JSON.parse(data);
                    var retVal_code = JSON.parse(retVal.code);
                    $('#div-modal-spinner').hide();

                    if(retVal_code == 200){
                        $('#modal-status-alert-title').text("GlueFS 삭제");
                        $('#modal-status-alert-body').text("GlueFS 삭제가 완료되었습니다.");
                        $('#div-modal-status-alert').show();

                        sessionStorage.removeItem('type');
                    }
                    else{
                        $('#modal-status-alert-title').text("GlueFS 삭제");
                        $('#modal-status-alert-body').text("GlueFS 삭제가 실패했습니다.");
                        $('#div-modal-status-alert').show();
                    }
                }).catch(function(){
                    createLoggerInfo("GlueFS destroy failed");
                });
            }
            else{
                $('#modal-status-alert-title').text("GlueFS 삭제");
                $('#modal-status-alert-body').text("GlueFS 삭제가 실패했습니다.");
                $('#div-modal-status-alert').show();
            }
        }).catch(function(){
                createLoggerInfo("GlueFS delete failed");
        });
    }
    else if(delete_session == 'nfs_delete'){
        $('#div-modal-spinner-header-txt').text('NFS 삭제 중');
        $('#div-modal-spinner').show();
        cockpit.spawn(['python3', pluginpath + '/python/glue/nfs.py','destroy']).then(function(data){
            var retVal = JSON.parse(data);
            var retVal_code = JSON.parse(retVal.code);

            $('#div-modal-spinner').hide();

            if(retVal_code == 200){
                $('#modal-status-alert-title').text("NFS 삭제");
                $('#modal-status-alert-body').text("NFS 삭제가 완료되었습니다.");
                $('#div-modal-status-alert').show();

                sessionStorage.removeItem('type');
            }
            else{
                $('#modal-status-alert-title').text("NFS 삭제");
                $('#modal-status-alert-body').text("NFS 삭제가 실패했습니다.");
                $('#div-modal-status-alert').show();
            }
        }).catch(function(){
            createLoggerInfo("NFS delete failed");
        });
    }
    else if(delete_session == 'smb_delete'){
        $('#div-modal-spinner-header-txt').text('SMB 삭제 중');
        $('#div-modal-spinner').show();
        cockpit.spawn(['python3', pluginpath + '/python/glue/smb.py','delete']).then(function(data){
            var retVal = JSON.parse(data);

            $('#div-modal-spinner').hide();

            if(retVal.code == 200){
                $('#div-modal-all-delete').hide();
                $('#modal-status-alert-title').text("SMB 삭제");
                $('#modal-status-alert-body').text("SMB 삭제가 완료되었습니다.");
                $('#div-modal-status-alert').show();

                sessionStorage.removeItem('type');
            }
            else{
                $('#modal-status-alert-title').text("SMB 삭제");
                $('#modal-status-alert-body').text("SMB 삭제가 실패했습니다.");
                $('#div-modal-status-alert').show();
            }
        }).catch(function(){
            createLoggerInfo("SMB delete failed");
        })
    }
    else if(delete_session == 'iscsi_delete'){
        $('#div-modal-spinner-header-txt').text('iSCSI 삭제 중');
        $('#div-modal-spinner').show();
        cockpit.spawn(['python3', pluginpath + '/python/glue/iscsi.py', 'destroy']).then(function(data){
            var retVal = JSON.parse(data);

            $('#div-modal-spinner').hide();

            if(retVal.code == 200){
                $('#div-modal-all-delete').hide();
                $('#modal-status-alert-title').text("iSCSI 삭제");
                $('#modal-status-alert-body').text("iSCSI 삭제가 완료되었습니다.");
                $('#div-modal-status-alert').show();

                sessionStorage.removeItem('type');
            }
            else{
                $('#modal-status-alert-title').text("SMB 삭제");
                $('#modal-status-alert-body').text("SMB 삭제가 실패했습니다.");
                $('#div-modal-status-alert').show();
            }
        }).catch(function(){
            createLoggerInfo("iSCSI delete failed");
        })
    }
});











function iscsiCheckInfo(type){
    $('#iscsi-status').html("상태 체크 중 &bull;&bull;&bull;&nbsp;&nbsp;&nbsp;<svg class='pf-c-spinner pf-m-md' role='progressbar' aria-valuetext='Loading...' viewBox='0 0 100 100' ><circle class='pf-c-spinner__path' cx='50' cy='50' r='45' fill='none'></circle></svg>");
    $("#iscsi-color").attr('class','pf-c-label pf-m-orange');
    $("#iscsi-icon").attr('class','fas fa-fw fa-exclamation-triangle');

    var session = localStorage.getItem('iscsi');

    cockpit.spawn(['python3', pluginpath + '/python/glue/iscsi.py', 'status']).then(function(data){
        var retVal = JSON.parse(data);
        var retVal_val = JSON.parse(retVal.val);
        return
        if(retVal_val[0].status.running == "1"){
            cockpit.spawn(['python3', pluginpath + '/python/glue/iscsi.py', 'list']).then(function(data){
                var retVal = JSON.parse(data);
                var retVal_val = JSON.parse(retVal.val);
                if(retVal.code == 200){

                    cockpit.spawn(['python3', pluginpath + '/python/glue/iscsi.py', 'image']).then(function(data){
                        var image = JSON.parse(data);
                        var image_val = JSON.parse(image.val);
                        console.log(image_val);
                        if(image.code == 200){
                            if(type == 'delete'){
                                $('#iscsi-tbody tr').remove();
                                $('#iscsi-tbody').html('<tbody role="rowgroup" id="iscsi-tbody"></tbody>');
                            }
                            for(var i = 0; i < retVal_val.length; i++){
                                $('#iscsi-tbody').append('<tr role="row"><td role="cell" data-label="대상">'+ retVal_val[i].target_iqn+'</td>'
                                                          + '<td role="cell" data-label="포털">'+ retVal_val[i].portals[0].ip+ '</td>'
                                                          + '<td role="cell" data-label="이미지">'+ image_val[0].value[0].name+ '</td>'
                                                          + '<td role="cell" data-label="크기">'+ Byte(image_val[0].value[0].size)+ '</td>'
                                                          + '<td class="pf-c-table__icon" role="cell" data-label="편집"><button class="pf-c-dropdown__toggle pf-m-plain" id="iscsi-edit" aria-expanded="false" type="button" aria-label="Actions"><i class="fas fa-edit"></i></td>'
                                                          + '<td class="pf-c-table__icon" role="cell" data-label="삭제"><button class="pf-c-dropdown__toggle pf-m-plain" id="iscsi-delete" aria-expanded="false" type="button" aria-label="Actions"><i class="fas fa-trash"></i></td></tr>');
                            }
                            $('#iscsi-status').text("Health OK");
                            $('#iscsi-color').attr('class','pf-c-label pf-m-green');
                            $('#iscsi-icon').attr('class','fas fa-fw fas fa-fw fa-check-circle');

                        }
                    })
                }
            })
        }
        else{
            if(session == "stop"){
                $('#iscsi-status').text("Stop");
                $('#iscsi-color').attr('class','pf-c-label pf-m-red');
                $('#iscsi-icon').attr('class','fas fa-fw fa-exclamation-triangle');
            }
            else{
                $('#iscsi-status').text("Health Err");
                $('#iscsi-color').attr('class','pf-c-label pf-m-red');
                $('#iscsi-icon').attr('class','fas fa-fw fa-exclamation-triangle');
            }
        }
    });
}
/**
 * Meathod Name : sambaCheckInfo
 * Date Created : 2023.06.02
 * Writer  : 정민철
 * Description : 삼바 서비스 상태 동작 확인 및 정보 확인
 * Parameter : 없음
 * Return  : 없음
 * History  : 2023.05.31 최초 작성
 */
function sambaCheckInfo(){
    var action = localStorage.getItem('smb');

    $('#smb-status').html("상태 체크 중 &bull;&bull;&bull;&nbsp;&nbsp;&nbsp;<svg class='pf-c-spinner pf-m-md' role='progressbar' aria-valuetext='Loading...' viewBox='0 0 100 100' ><circle class='pf-c-spinner__path' cx='50' cy='50' r='45' fill='none'></circle></svg>");
    $("#smb-color").attr('class','pf-c-label pf-m-orange');
    $("#smb-icon").attr('class','fas fa-fw fa-exclamation-triangle');

    cockpit.spawn(['python3', pluginpath + '/python/glue/smb.py','detail']).then(function(data){
        var retVal_detail = JSON.parse(data);
        if(retVal_detail.code == 200){
            cockpit.spawn(['python3', pluginpath + '/python/glue/smb.py','status', '-sn','smb']).then(function(data){
                var retVal_status = JSON.parse(data);
                if(retVal_status.code == 500){
                    if(action == 'stop'){
                        ServiceQuota('smb');

                        $('#smb-path').text("/fs");
                        $('#smb-mount-path').text("/smb");
                        $('#smb-access-ip').text(retVal_detail.val.ip_address);
                        $('#smb-status').text("Stop");
                        $('#smb-color').attr('class','pf-c-label pf-m-red');
                        $('#smb-icon').attr('class','fas fa-fw fa-exclamation-triangle');
                        $('#smb-edit').attr('class','pf-c-dropdown__toggle pf-m-plain pf-m-enabled');
                        $('#menu-item-set-smb-construction').hide();
                        $('#menu-item-set-smb-delete').show();
                    }
                    else{
                        cleanSambaInfo();
                        $('#smb-status').text("Health Err");
                        $('#smb-color').attr('class','pf-c-label pf-m-red');
                        $('#smb-icon').attr('class','fas fa-fw fa-exclamation-triangle');
                        $('#smb-edit').attr('class','pf-c-dropdown__toggle pf-m-plain pf-m-disabled');
                        $("#form-select-file-system-service-control option[value=smb]").hide();
                        $('#menu-item-set-smb-construction').show();
                        $('#menu-item-set-smb-delete').hide();
                    }
                }
                else{
                    ServiceQuota('smb');

                    $('#smb-path').text("/fs");
                    $('#smb-mount-path').text("/smb");
                    $('#smb-access-ip').text(retVal_detail.val.ip_address);
                    $('#smb-status').text("Health OK");
                    $('#smb-color').attr('class','pf-c-label pf-m-green');
                    $('#smb-icon').attr('class','fas fa-fw fas fa-fw fa-check-circle');
                    $('#smb-edit').attr('class','pf-c-dropdown__toggle pf-m-plain pf-m-enabled');
                    $('#menu-item-set-smb-construction').hide();
                    $('#menu-item-set-smb-delete').show();
                }
            }).catch(function(){
                createLoggerInfo("SMB status 조회 실패");
            });
        }
        else{
            $('#smb-status').text("Health Err");
            $('#smb-color').attr('class','pf-c-label pf-m-red');
            $('#smb-icon').attr('class','fas fa-fw fa-exclamation-triangle');
            $('#smb-edit').attr('class','pf-c-dropdown__toggle pf-m-plain pf-m-disabled');
            $("#form-select-file-system-service-control option[value=smb]").hide();
            $('#menu-item-set-smb-construction').show();
            $('#menu-item-set-smb-delete').hide();
            cleanSambaInfo();
        }
    }).catch(function(){
        createLoggerInfo("SMB detail 조회 실패");
    });
}
function cleanSambaInfo(){
    $('#smb-path').text("N/A");
    $('#smb-mount-path').text("N/A");
    $('#smb-access-ip').text("N/A");
    $('#smb-usage').text("N/A");
}
/**
 * Meathod Name : gluefsCheckInfo
 * Date Created : 2023.06.02
 * Writer  : 정민철
 * Description : gluefs 서비스 상태 동작 확인 및 정보 확인
 * Parameter : 없음
 * Return  : 없음
 * History  : 2023.05.31 최초 작성
 */
function gluefsCheckInfo(){
    $('#gluefs-status').html("상태 체크 중 &bull;&bull;&bull;&nbsp;&nbsp;&nbsp;<svg class='pf-c-spinner pf-m-md' role='progressbar' aria-valuetext='Loading...' viewBox='0 0 100 100' ><circle class='pf-c-spinner__path' cx='50' cy='50' r='45' fill='none'></circle></svg>");
    $("#gluefs-color").attr('class','pf-c-label pf-m-orange');
    $("#gluefs-icon").attr('class','fas fa-fw fa-exclamation-triangle');

    cockpit.spawn(['python3', pluginpath + '/python/glue/gluefs.py','status']).then(function(data){
        var retVal = JSON.parse(data);
        var retVal_code_status = JSON.parse(retVal.code);
        var retVal_val_status = JSON.parse(retVal.val);
        if(retVal_code_status == 200){
            if(retVal_val_status[0] == undefined){
                cleanGluefsInfo();
                $('#gluefs-status').text("Health Err");
                $('#gluefs-color').attr('class','pf-c-label pf-m-red');
                $('#gluefs-icon').attr('class','fas fa-fw fa-exclamation-triangle');
                $('#gluefs-edit').attr('class','pf-c-dropdown__toggle pf-m-plain pf-m-disabled');
                $("#form-select-file-system-service-control option[value=gluefs]").hide();
                $('#menu-item-set-gluefs-construction').show();
                $('#menu-item-set-gluefs-delete').hide();
            }
            else{
                cockpit.spawn(['python3', pluginpath + '/python/glue/gluefs.py','detail']).then(function(data){
                    var retVal = JSON.parse(data);
                    var retVal_code_detail = JSON.parse(retVal.code);
                    var retVal_val_detail = JSON.parse(retVal.val);
                    console.log(retVal_val_detail);
                    if(retVal_code_detail == 200){
                        gwvmEtcHostIp('gluefs');
                        ServiceQuota('gluefs');
                            if(retVal_val_status[0].status.running == 2){

                                $('#gluefs-mount-path').text("/gluefs");
                                $('#gluefs-status').text("Health OK");
                                $('#gluefs-color').attr('class','pf-c-label pf-m-green');
                                $('#gluefs-icon').attr('class','fas fa-fw fas fa-fw fa-check-circle');
                                $('#gluefs-edit').attr('class','pf-c-dropdown__toggle pf-m-plain pf-m-enabled');
                                $('#menu-item-set-gluefs-construction').hide();
                                $('#menu-item-set-gluefs-delete').show();
                            }
                            else {

                                $('#gluefs-mount-path').text("/gluefs");
                                $('#gluefs-status').text("Stop");
                                $('#gluefs-color').attr('class','pf-c-label pf-m-red');
                                $('#gluefs-icon').attr('class','fas fa-fw fa-exclamation-triangle');
                                $('#gluefs-edit').attr('class','pf-c-dropdown__toggle pf-m-plain pf-m-enabled');
                                $('#menu-item-set-gluefs-construction').hide();
                                $('#menu-item-set-gluefs-delete').show();
                            }
                    }
                    else{
                        cleanGluefsInfo();
                        $('#gluefs-status').text("Health Err");
                        $('#gluefs-color').attr('class','pf-c-label pf-m-red');
                        $('#gluefs-icon').attr('class','fas fa-fw fa-exclamation-triangle');
                        $('#gluefs-edit').attr('class','pf-c-dropdown__toggle pf-m-plain pf-m-disabled');
                        $("#form-select-file-system-service-control option[value=gluefs]").hide();
                        $('#menu-item-set-gluefs-construction').show();
                        $('#menu-item-set-gluefs-delete').hide();
                    }
                }).catch(function(){
                    createLoggerInfo("GlueFS status 조회 실패");
                });
            }
        }
        else{
            cleanGluefsInfo();
            $('#gluefs-status').text("Health Err");
            $('#gluefs-color').attr('class','pf-c-label pf-m-red');
            $('#gluefs-icon').attr('class','fas fa-fw fa-exclamation-triangle');
            $('#gluefs-edit').attr('class','pf-c-dropdown__toggle pf-m-plain pf-m-disabled');
            $("#form-select-file-system-service-control option[value=gluefs]").hide();
            $('#menu-item-set-gluefs-construction').show();
            $('#menu-item-set-gluefs-delete').hide();

        }
    }).catch(function(){
        createLoggerInfo("GlueFS detail 조회 실패");
    });
}
/**
 * Meathod Name : cleanGluefsInfo
 * Date Created : 2023.06.02
 * Writer  : 정민철
 * Description : gluefs 구성 초기화
 * Parameter : 없음
 * Return  : 없음
 * History  : 2023.05.31 최초 작성
 */
function cleanGluefsInfo(){
    $('#gluefs-path').text("N/A");
    $('#gluefs-mount-path').text("N/A");
    $('#gluefs-access-ip').text("N/A");
    $('#gluefs-usage').text("N/A");
}
/**
 * Meathod Name : nfsCheckInfo
 * Date Created : 2023.06.02
 * Writer  : 정민철
 * Description : nfs 서비스 상태 동작 확인 및 정보 확인
 * Parameter : 없음
 * Return  : 없음
 * History  : 2023.05.31 최초 작성
 */
function nfsCheckInfo(){
    $('#nfs-status').html("상태 체크 중 &bull;&bull;&bull;&nbsp;&nbsp;&nbsp;<svg class='pf-c-spinner pf-m-md' role='progressbar' aria-valuetext='Loading...' viewBox='0 0 100 100' ><circle class='pf-c-spinner__path' cx='50' cy='50' r='45' fill='none'></circle></svg>");
    $("#nfs-color").attr('class','pf-c-label pf-m-orange');
    $("#nfs-icon").attr('class','fas fa-fw fa-exclamation-triangle');

    cockpit.spawn(['python3', pluginpath + '/python/glue/nfs.py','status']).then(function(data){
        var retVal = JSON.parse(data);
        var retVal_code_status = JSON.parse(retVal.code);
        var retVal_val_status = JSON.parse(retVal.val);

        if(retVal_code_status == 200){
            if(retVal_val_status[0] == undefined){
                cleanNfsInfo();
                $('#nfs-status').text("Health Err");
                $('#nfs-color').attr('class','pf-c-label pf-m-red');
                $('#nfs-icon').attr('class','fas fa-fw fa-exclamation-triangle');
                $('#nfs-edit').attr('class','pf-c-dropdown__toggle pf-m-plain pf-m-disabled');
                $("#form-select-file-system-service-control option[value=nfs]").hide();
                $('#menu-item-set-nfs-construction').show();
                $('#menu-item-set-nfs-delete').hide();
            }
            else{
                cockpit.spawn(['python3', pluginpath + '/python/glue/nfs.py','detail']).then(function(data){
                    var retVal = JSON.parse(data);
                    var retVal_code_detail = JSON.parse(retVal.code);
                    var retVal_val_detail = JSON.parse(retVal.val);
                    console.log(retVal_val_detail);

                    if(retVal_code_detail == 200){
                        gwvmEtcHostIp('nfs');
                        ServiceQuota('nfs');
                            if(retVal_val_status[0].status.running == 1){

                                $('#nfs-path').text("/fs");
                                $('#nfs-mount-path').text(retVal_val_detail.path);
                                $('#nfs-status').text("Health OK");
                                $('#nfs-color').attr('class','pf-c-label pf-m-green');
                                $('#nfs-icon').attr('class','fas fa-fw fas fa-fw fa-check-circle');
                                $('#nfs-edit').attr('class','pf-c-dropdown__toggle pf-m-plain pf-m-enabled');
                                $('#menu-item-set-nfs-construction').hide();
                                $('#menu-item-set-nfs-delete').show();
                            }
                            else{

                                $('#nfs-path').text("/fs");
                                $('#nfs-mount-path').text(retVal_val_detail.path);
                                $('#nfs-status').text("Stop");
                                $('#nfs-color').attr('class','pf-c-label pf-m-red');
                                $('#nfs-icon').attr('class','fas fa-fw fa-exclamation-triangle');
                                $('#nfs-edit').attr('class','pf-c-dropdown__toggle pf-m-plain pf-m-enabled');
                                $('#menu-item-set-nfs-construction').hide();
                                $('#menu-item-set-nfs-delete').show();
                            }
                    }
                    else{
                        cleanNfsInfo();
                        $('#nfs-status').text("Health Err");
                        $('#nfs-color').attr('class','pf-c-label pf-m-red');
                        $('#nfs-icon').attr('class','fas fa-fw fa-exclamation-triangle');
                        $('#nfs-edit').attr('class','pf-c-dropdown__toggle pf-m-plain pf-m-disabled');
                        $("#form-select-file-system-service-control option[value=nfs]").hide();
                        $('#menu-item-set-nfs-construction').show();
                        $('#menu-item-set-nfs-delete').hide();
                    }
                }).catch(function(){
                    createLoggerInfo("NFS status 조회 실패");
                });
            }
        }
        else{
            cleanNfsInfo();
            $('#nfs-status').text("Health Err");
            $('#nfs-color').attr('class','pf-c-label pf-m-red');
            $('#nfs-icon').attr('class','fas fa-fw fa-exclamation-triangle');
            $('#nfs-edit').attr('class','pf-c-dropdown__toggle pf-m-plain pf-m-disabled');
            $("#form-select-file-system-service-control option[value=nfs]").hide();
            $('#menu-item-set-nfs-construction').show();
            $('#menu-item-set-nfs-delete').hide();
        }
    }).catch(function(){
        createLoggerInfo("NFS detail 조회 실패");
    });

}
/**
 * Meathod Name : ServiceQuota
 * Date Created : 2023.09.05
 * Writer  : 정민철
 * Description : 스토리지 서비스 사용량 확인
 * Parameter : type
 * Return  : 없음
 * History  : 2023.09.05 최초 작성
 */
function ServiceQuota(type){

    if (type == 'smb'){
        cockpit.spawn(['python3', pluginpath + '/python/glue/smb.py','smb-quota']).then(function(data){
            var retVal = JSON.parse(data);
            if(retVal.code == 200){
                $('#smb-usage').text(retVal.val.usage+"B/"+Byte(retVal.val.quota));

            }
        });
    }else if(type == 'gluefs'){
        cockpit.spawn(['python3', pluginpath + '/python/glue/gluefs.py', 'gluefs-quota']).then(function(data){
            var retVal = JSON.parse(data);
            if(retVal.code == 200){
                $('#gluefs-usage').text(retVal.val.usage+"B/"+Byte(retVal.val.quota));
                $('#gluefs-path').text(retVal.val.fs_path);
            }
        });
    }else if(type == 'nfs'){
        cockpit.spawn(['python3', pluginpath + '/python/glue/nfs.py', 'nfs-quota']).then(function(data){
            var retVal = JSON.parse(data);
            if(retVal.code == 200){
                $('#nfs-usage').text(retVal.val.usage+"B/"+Byte(retVal.val.quota));
            }
        });
    }
}
/**
 * Meathod Name : gwvmEtcHostIp
 * Date Created : 2023.08.30
 * Writer  : 정민철
 * Description : gluefs, nfs 접근 IP 구성
 * Parameter : type
 * Return  : 없음
 * History  : 2023.08.30 최초 작성
 */
function gwvmEtcHostIp(type){
     cockpit.spawn(['grep','gwvm-mngt','/etc/hosts']).then(function(data){
        var ip = data.split('\t');
            if(type == 'gluefs'){
                $('#gluefs-access-ip').text(ip[0]);
            }else if(type == 'nfs'){
                $('#nfs-access-ip').text(ip[0]);
            }
    });
}
/**
 * Meathod Name : cleanNfsInfo
 * Date Created : 2023.08.30
 * Writer  : 정민철
 * Description : nfs 구성 초기화
 * Parameter : 없음
 * Return  : 없음
 * History  : 2023.08.30 최초 작성
 */
function cleanNfsInfo(){
    $('#nfs-path').text("N/A");
    $('#nfs-mount-path').text("N/A");
    $('#nfs-access-ip').text("N/A");
    $('#nfs-usage').text("N/A");
}
/**
 * Meathod Name : Byte
 * Date Created : 2023.08.30
 * Writer  : 정민철
 * Description : 용량 숫자를 단위에 맞춰 byte단위로 변경하는 함수
 * Parameter : 없음
 * Return  : 없음
 * History  : 2023.08.30 최초 작성
 */
function Byte(size){
    var ret_byte
    var ret_byte_name


    if(size < (1024*1024))
    {
        ret_byte = parseFloat(size)/1024;
        ret_byte_name = "KB";
    }
    else if (size < (1024*1024*1024))
    {
        ret_byte = parseFloat(size)/(1024*1024);
        ret_byte_name = "MB";
    }
    else if (size < (1024*1024*1024*1024)){
        ret_byte = parseFloat(size)/(1024*1024*1024);
        ret_byte_name = "GB";
    }
    else if (size < (1024*1024*1024*1024*1024)){
        ret_byte = parseFloat(size)/(1024*1024*1024*1024);
        ret_byte_name = "TB";
    }

    var bytes = parseInt(ret_byte);

    return (bytes + ret_byte_name);

}
/**
 * Meathod Name : gwvmInfoSet
 * Date Created : 2023.05.25
 * Writer  : 배태주
 * Description : 게이트웨이 가상머신 생성 전 입력받은 값의 유효성 검사
 * Parameter : 없음
 * Return  : 없음
 * History  : 2023.05.25 최초 작성
 */
function gwvmInfoSet(){
    $('#gwvm-status').html("상태 체크 중 &bull;&bull;&bull;&nbsp;&nbsp;&nbsp;<svg class='pf-c-spinner pf-m-md' role='progressbar' aria-valuetext='Loading...' viewBox='0 0 100 100' ><circle class='pf-c-spinner__path' cx='50' cy='50' r='45' fill='none'></circle></svg>");
    $("#gwvm-back-color").attr('class','pf-c-label pf-m-orange');
    $("#gwvm-cluster-icon").attr('class','fas fa-fw fa-exclamation-triangle');
    
    //디테일 정보 가져오기
    fetch('https://10.10.5.11:8080/api/v1/gwvm/detail/cell',{
        method: 'GET'
    }).then(res => res.json()).then(data => {
        var retDetailVal = JSON.parse(data.Message);
        console.log(retDetailVal)
        if (retDetailVal.code == "200" || retDetailVal.val["role"] == 'Running') {
            fetch('https://10.10.5.11:8080/api/v1/gwvm/cell',{
                method: 'GET'
            }).then(res => res.json()).then(data => {
                var retVal = JSON.parse(data.Message);
                console.log(retVal)
                if(retVal.code == "200"){
                    if(retVal.val["role"] == "Started"){
                        $("#gwvm-status").text(retDetailVal.val["role"]);
                        $("#gwvm-back-color").attr('class','pf-c-label pf-m-green');
                        $("#gwvm-cluster-icon").attr('class','fas fa-fw fa-check-circle');

                        $('#td_gwvm_started_host').text(retVal.val["started"]);
                        $('#td_gwvm_cpu_mem').text(retVal.val['CPU(s)'] + " vCore / " + toBytes(retVal.val['Max memory']));
                        $('#td_gwvm_ip').text(retVal.val["ip"]);
                        $('#td_gwvm_root_disk').text(retVal.val["disk_cap"] + " (사용가능 " + retVal.val["disk_phy"] + " / 사용률 " + retVal.val["disk_usage_rate"] + ")");

                        // 마이그레이션 노드 옵션 설정
                        var nodeText = '( ';
                        var selectHtml = '<option selected="" value="null">노드를 선택해주세요.</option>';
                        $('#form-select-gateway-vm-migration-node option').remove();
                        for(var i=0; i<Object.keys(retDetailVal.val.clustered_host).length; i++){
                            nodeText = nodeText +retDetailVal.val.clustered_host[i];
                            if(retDetailVal.val.clustered_host[i] != retDetailVal.val.started){
                                selectHtml = selectHtml + '<option value="' + retDetailVal.val.clustered_host[i] + '">' + retDetailVal.val.clustered_host[i] + '</option>';
                            }
                            if(i == (Object.keys(retDetailVal.val.clustered_host).length - 1)){

                                nodeText = nodeText + ' )';
                            }else{
                                nodeText = nodeText + ', ';
                            }
                        }
                        $('#form-select-gateway-vm-migration-node').append(selectHtml);

                        //게이트웨이 버튼 디스플레이 액션
                        $("#button-gateway-vm-setup").hide();
                        $("#menu-item-gateway-vm-setup").hide();
                        $("#menu-item-gateway-vm-setup").removeClass('pf-m-disabled');
                        $("#menu-item-gateway-vm-start").addClass('pf-m-disabled');
                        $("#menu-item-gateway-vm-stop").removeClass('pf-m-disabled');
                        $("#menu-item-gateway-vm-destroy").addClass('pf-m-disabled');
                        $("#menu-item-gateway-vm-cleanup").removeClass('pf-m-disabled');
                        $("#menu-item-gateway-vm-migrate").removeClass('pf-m-disabled');
                    }else if(retVal.val["role"] == "Stopped") {
                        $("#gwvm-status").text(retDetailVal.val["role"]);
                        cleanGwvmInfo();
                        //게이트웨이 버튼 디스플레이 액션
                        $("#button-gateway-vm-setup").hide();
                        $("#menu-item-gateway-vm-setup").hide();
                        $("#menu-item-gateway-vm-start").removeClass('pf-m-disabled');
                        $("#menu-item-gateway-vm-stop").addClass('pf-m-disabled');
                        $("#menu-item-gateway-vm-destroy").removeClass('pf-m-disabled');
                        $("#menu-item-gateway-vm-cleanup").addClass('pf-m-disabled');
                        $("#menu-item-gateway-vm-migrate").addClass('pf-m-disabled');
                    }else{
                        allDisableConfig(retDetailVal.val["role"]);
                    }
                } else {
                    allDisableConfig(retDetailVal.val["role"]);
                    console.log("err1");
                }
            }).catch(function(data){
                allDisableConfig("Health Err");
                createLoggerInfo("게이트웨이 가상머신 정보 조회 실패 "+data);
                console.log("게이트웨이 가상머신 정보 조회 실패 "+data);
            });
        } else if (retDetailVal.code == "200" || retDetailVal.val["role"] == 'Stopped') {
            $("#gwvm-status").text("Stopped1");
            console.log("err2");
        } else if (retDetailVal.code == "400") {
            allDisableConfig("Not configured");
            stateBeforeConfig();
            
            console.log("Not configured");
        } else {
            allDisableConfig(retDetailVal.val["role"]);
            console.log("err4");
        }
    }).catch(function(data){
        allDisableConfig("Health Err");
        createLoggerInfo("게이트웨이 가상머신 상태 정보 상세 조회 실패 "+data);
        console.log("게이트웨이 가상머신 상태 정보 상세 조회 실패 "+data);
    });
}

// Gwvm 구성 전 상태
function stateBeforeConfig(){
    $("#button-gateway-vm-setup").show();
    $("#menu-item-gateway-vm-setup").show();
    $("#menu-item-gateway-vm-setup").removeClass('pf-m-disabled');
    $("#menu-item-gateway-vm-start").addClass('pf-m-disabled');
    $("#menu-item-gateway-vm-stop").addClass('pf-m-disabled');
    $("#menu-item-gateway-vm-destroy").addClass('pf-m-disabled');
    $("#menu-item-gateway-vm-cleanup").addClass('pf-m-disabled');
    $("#menu-item-gateway-vm-migrate").addClass('pf-m-disabled');
}

function stopStatusConfig(){
    cleanGwvmInfo();
    $("#gwvm-status").text("Stopped");
    //게이트웨이 버튼 디스플레이 액션
    $("#button-gateway-vm-setup").hide();
    $("#menu-item-gateway-vm-setup").hide();
    $("#menu-item-gateway-vm-start").removeClass('pf-m-disabled');
    $("#menu-item-gateway-vm-stop").addClass('pf-m-disabled');
    $("#menu-item-gateway-vm-destroy").removeClass('pf-m-disabled');
    $("#menu-item-gateway-vm-cleanup").addClass('pf-m-disabled');
    $("#menu-item-gateway-vm-migrate").addClass('pf-m-disabled');
}

function allDisableConfig(text){
    cleanGwvmInfo();
    $("#gwvm-status").text(text);
    $("#button-gateway-vm-setup").hide();
    $("#menu-item-gateway-vm-setup").hide();
    $("#menu-item-gateway-vm-start").addClass('pf-m-disabled');
    $("#menu-item-gateway-vm-stop").addClass('pf-m-disabled');
    $("#menu-item-gateway-vm-destroy").addClass('pf-m-disabled');
    $("#menu-item-gateway-vm-cleanup").addClass('pf-m-disabled');
    $("#menu-item-gateway-vm-migrate").addClass('pf-m-disabled');
}

function cleanGwvmInfo(){
    $("#gwvm-back-color").attr('class','pf-c-label pf-m-red');
    $("#gwvm-cluster-icon").attr('class','fas fa-fw fa-exclamation-triangle');
    $('#td_gwvm_started_host').text("N/A");
    $('#td_gwvm_cpu_mem').text("N/A");
    $('#td_gwvm_ip').text("N/A");
    $('#td_gwvm_gw').text("N/A");
    $('#td_gwvm_root_disk').text("N/A");
}

/*
    용량 숫자를 단위에 맞춰 bytes단위로 변경하는 함수
    ex) ccvm_instance.toBytes("1.5 GiB") == 1610612736

    파라미터 설명 : size: str: 용량을 나타내는 문자열
    반환값 : float: bytes 단위의 용량
*/
function toBytes(size){
    var ret_bytes
    if( size.search('KB') >= 0) ret_bytes = parseFloat(size)*1000
    else if( size.search('KiB') >= 0) ret_bytes =  parseFloat(size)*1024
    else if( size.search('MB') >= 0) ret_bytes =  parseFloat(size)*1000*1000
    else if( size.search('MiB') >= 0) ret_bytes =  parseFloat(size)*1024*1024
    else if( size.search('GB') >= 0) ret_bytes =  parseFloat(size)*1000*1000*1000
    else if( size.search('GiB') >= 0) ret_bytes =  parseFloat(size)*1024*1024*1024
    else if( size.search('TB') >= 0) ret_bytes =  parseFloat(size)*1000*1000*1000*1000
    else if( size.search('TiB') >= 0) ret_bytes =  parseFloat(size)*1024*1024*1024*1024
    else if( size.search('PB') >= 0) ret_bytes =  parseFloat(size)*1000*1000*1000*1000*1000
    else if( size.search('PiB') >= 0) ret_bytes =  parseFloat(size)*1024*1024*1024*1024*1024

    var bytes = parseInt(ret_bytes);

    var s = ['bytes', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'];

    var e = Math.floor(Math.log(bytes) / Math.log(1024));

    if (e == "-Infinity") return "0 " + s[0];
    else
        return (bytes / Math.pow(1024, Math.floor(e))) + " " + s[e];

}

function bytesToSize(bytes) {
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB']
    if (bytes === 0) return '0 B'
    const i = parseInt(Math.floor(Math.log(bytes) / Math.log(1024)), 10)
    if (i === 0) return `${bytes} ${sizes[i]})`
    return `${(bytes / (1024 ** i)).toFixed(1)} ${sizes[i]}`
}

function toggleAction(id,index){
    $('#'+id+index).toggle();
}

$('#button-storage-dashboard-connect').on('click', function(){
    // storageCenter url 링크 주소 가져오기
    createLoggerInfo("button-storage-dashboard-connect click");
    cockpit.spawn(["python3", pluginpath+"/python/url/create_address.py", "storageCenter"])
    .then(function(data){
        var retVal = JSON.parse(data);
        if(retVal.code == 200){
            // 스토리지센터 연결
            window.open(retVal.val);
        }else{
            $("#modal-status-alert-title").html("스토리지센터 연결");
            $("#modal-status-alert-body").html(retVal.val);
            $('#div-modal-status-alert').show();
        }
    })
    .catch(function(err){
        createLoggerInfo(":::create_address.py storageCenter Error:::");
        console.log(":::create_address.py storageCenter Error:::"+ err);
    });
});

/**
 * Meathod Name : glueVmList
 * Date Created : 2024.02.22
 * Writer  : 배태주
 * Description : 게이트웨이 가상머신 생성 전 입력받은 값의 유효성 검사
 * Parameter : 없음
 * Return  : 없음
 * History  : 2024.02.22 최초 작성
 */
function glueVmList(){
    fetch('https://10.10.5.11:8080/api/v1/glue/hosts',{
        method: 'GET'
    }).then(res => res.json()).then(data => {
        $('#glue-vm-list tr').remove();
        console.log(data)

        for(var i=0; i < data.length; i++){
            let insert_tr = "";
                                                    
            insert_tr += '<tr role="row">';

            insert_tr += '<tr role="row">';
            insert_tr += '    <td role="cell" data-label="이름" id="td_glue_host_name">'+data[i].hostname+'</td>';
            insert_tr += '    <td role="cell" data-label="상태">';
            if(data[i].status == ''){
                insert_tr += '        <span class="pf-c-label pf-m-green">';
                insert_tr += '            <span class="pf-c-label__content">';
                insert_tr += '                <span class="pf-c-label__icon">';
                insert_tr += '                    <i class="fas fa-fw fa-check-circle" aria-hidden="true"></i>';
                insert_tr += '                </span><div>Online</div>';
                insert_tr += '            </span>';
                insert_tr += '        </span>';
            }else{
                insert_tr += '        <span class="pf-c-label pf-m-orange">';
                insert_tr += '            <span class="pf-c-label__content">';
                insert_tr += '                <span class="pf-c-label__icon">';
                insert_tr += '                    <i class="fas fa-fw fa-exclamation-triangle" aria-hidden="true"></i>';
                insert_tr += '                </span><div>'+data[i].status+'</div>';
                insert_tr += '            </span>';
                insert_tr += '        </span>';
            }
            insert_tr += '    </td>';
            insert_tr += '    <td role="cell" data-label="관리 IP" id="td_glue_host_mngt_ip">'+data[i].ip_address+'</td>';
            insert_tr += '    <td role="cell" data-label="스토리지 IP " id="td_glue_host_storage_ip">'+data[i].addr+'</td>';
            insert_tr += '</tr>';
            $("#glue-vm-list:last").append(insert_tr);
        }
    }).catch(function(data){
        createLoggerInfo("Glue 가상머신 정보 조회 실패 "+data);
        console.log("Glue 가상머신 정보 조회 실패 "+data);
    });
}

// glue 호스트 리스트 기능
$('#button-glue-hosts-list-setting').on('click', function(){
    $('#div-glue-hosts-list').toggle();
});

// glue 호스트 리스트 기능
$('input[name=glue-hosts-list]').on('click', function(){
    var cnt = 0;
    var el = "";
    $('input[type=checkbox][name="glue-hosts-list"]').each(function() {
        if(this.checked){
            if(cnt==0){
                el = this.value
            }else{
                el += ", "+this.value
            }
            cnt++
        }
    });
    $('#form-input-nfs-cluster-placement-hosts').val(el);
});